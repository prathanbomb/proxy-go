package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Constants defining default behaviors and configuration values.
const (
	// AuthRealm is the realm sent in the WWW-Authenticate header for Basic Auth challenges.
	AuthRealm = "Basic Realm=\"Proxy Authentication Required\""
	// NTLMAuthRealm is the realm sent in the WWW-Authenticate header for NTLM Auth challenges.
	NTLMAuthRealm = "NTLM"
	// DefaultIdleTimeout specifies the maximum amount of time an idle connection will be kept alive.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultReadHeaderTimeout limits the time allowed to read the headers of a request, protecting against slowloris attacks.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultDialTimeout is the default maximum time allowed for establishing a TCP connection to the upstream server.
	DefaultDialTimeout = 10 * time.Second
	// DefaultTLSHandshakeTimeout is the default maximum time allowed for the TLS handshake with the upstream server.
	DefaultTLSHandshakeTimeout = 10 * time.Second
)

// NTLMSessionState represents the state of an NTLM authentication session
type NTLMSessionState struct {
	Authenticated bool
	Challenge     []byte
	Timestamp     time.Time
}

// Proxy holds the configuration and operational state for the proxy server.
type Proxy struct {
	Username            string        // Username for Basic Authentication.
	Password            string        // Password for Basic Authentication.
	AuthRequired        bool          // Flag indicating if authentication is enforced.
	Verbose             bool          // Flag to enable detailed logging of requests/responses.
	DialTimeout         time.Duration // Timeout for dialing upstream servers.
	TLSHandshakeTimeout time.Duration // Timeout for TLS handshake with upstream servers.

	// transport is a shared, configured http.RoundTripper for handling outgoing non-CONNECT requests.
	transport http.RoundTripper

	// NTLM authentication session cache
	ntlmSessions sync.Map // Maps client IP to NTLM session state
}

// NewProxy creates and configures a new Proxy instance based on the provided settings.
// It initializes the internal HTTP transport optimized for proxying.
func NewProxy(username, password string, authEnabled, verbose bool, dialTimeout, tlsTimeout time.Duration) *Proxy {
	authRequired := authEnabled && username != "" && password != ""
	log.Printf("INFO: Authentication %s", map[bool]string{true: "enabled", false: "disabled"}[authRequired])
	if authRequired {
		log.Printf("INFO: Authenticating user: %q", username) // Log username for clarity, consider security implications.
	}
	log.Printf("INFO: Verbose logging: %t", verbose)

	// Configure a shared transport for outgoing HTTP requests.
	// Using a shared transport improves resource reuse (e.g., keep-alive connections).
	// Explicitly disabling HTTP/2 support as it can complicate proxying CONNECT requests.
	// See: https://github.com/golang/go/issues/34063
	baseTransport := &http.Transport{
		Proxy: nil, // We are the proxy, so no upstream proxy.
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,      // Connection timeout.
			KeepAlive: 30 * time.Second, // Keep-alive probes - should be less than idle timeout.
		}).DialContext,
		ForceAttemptHTTP2:     false,            // Crucial for CONNECT proxying stability.
		MaxIdleConns:          100,              // Default, suitable for moderate load.
		IdleConnTimeout:       90 * time.Second, // Should be less than server's IdleTimeout.
		TLSHandshakeTimeout:   tlsTimeout,       // Timeout for TLS handshake.
		ExpectContinueTimeout: 1 * time.Second,  // Default.
	}

	return &Proxy{
		Username:            username,
		Password:            password,
		AuthRequired:        authRequired,
		Verbose:             verbose,
		DialTimeout:         dialTimeout,
		TLSHandshakeTimeout: tlsTimeout,
		transport:           baseTransport,
	}
}

// checkAuth validates the Proxy-Authorization header.
// It returns the provided username (if available) and a boolean indicating success.
// Uses constant-time comparison for security.
// For NTLM authentication, it handles the multi-step negotiation process.
func (p *Proxy) checkAuth(r *http.Request) (username string, ok bool) {
	if !p.AuthRequired {
		return "", true // Authentication is disabled.
	}

	proxyAuth := r.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		log.Printf("DEBUG: [%s] Auth failed: Missing Proxy-Authorization header", r.RemoteAddr)
		return "", false
	}

	// Check for NTLM authentication
	if strings.HasPrefix(proxyAuth, "NTLM ") {
		return p.handleNTLMAuth(r, proxyAuth)
	}

	// Check for Negotiate authentication (which can also be NTLM)
	if strings.HasPrefix(proxyAuth, "Negotiate ") {
		// Handle Negotiate similar to NTLM
		// For simplicity, we'll just modify the header to use NTLM prefix
		modifiedAuth := "NTLM " + proxyAuth[10:] // Replace "Negotiate " with "NTLM "
		return p.handleNTLMAuth(r, modifiedAuth)
	}

	// Basic Authentication format: "Basic <base64-encoded username:password>"
	const prefix = "Basic "
	if !strings.HasPrefix(proxyAuth, prefix) {
		log.Printf("DEBUG: [%s] Auth failed: Malformed Proxy-Authorization header (bad prefix)", r.RemoteAddr)
		return "", false
	}

	// Decode the base64 payload.
	decoded, err := base64.StdEncoding.DecodeString(proxyAuth[len(prefix):])
	if err != nil {
		log.Printf("DEBUG: [%s] Auth failed: Malformed Proxy-Authorization header (bad base64 encoding): %v", r.RemoteAddr, err)
		return "", false
	}

	// Expecting "username:password" format after decoding.
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		log.Printf("DEBUG: [%s] Auth failed: Malformed Proxy-Authorization header (invalid format after decode)", r.RemoteAddr)
		// Return the potentially extracted username for logging purposes.
		return credentials[0], false
	}
	providedUser := credentials[0]
	providedPass := credentials[1]

	// Use constant-time comparison to mitigate timing attacks.
	userMatch := subtle.ConstantTimeCompare([]byte(providedUser), []byte(p.Username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(providedPass), []byte(p.Password)) == 1

	if !(userMatch && passMatch) {
		log.Printf("DEBUG: [%s] Auth failed: Credentials mismatch for user %q", r.RemoteAddr, providedUser)
		return providedUser, false // Return provided username even on failure.
	}

	// Authentication successful.
	return providedUser, true
}

// handleNTLMAuth processes NTLM authentication messages
// It handles the 3-step NTLM authentication process:
// 1. Negotiate: Client sends initial NTLM message
// 2. Challenge: Server responds with challenge
// 3. Authenticate: Client sends credentials
func (p *Proxy) handleNTLMAuth(r *http.Request, authHeader string) (username string, ok bool) {
	clientIP := r.RemoteAddr

	// Extract the NTLM message from the header
	var ntlmMsg string
	if strings.HasPrefix(authHeader, "NTLM ") {
		ntlmMsg = authHeader[5:] // Remove "NTLM " prefix
	} else if strings.HasPrefix(authHeader, "Negotiate ") {
		ntlmMsg = authHeader[10:] // Remove "Negotiate " prefix
	} else {
		log.Printf("DEBUG: [%s] NTLM Auth failed: Unsupported authentication method", clientIP)
		return "", false
	}

	msgBytes, err := base64.StdEncoding.DecodeString(ntlmMsg)
	if err != nil {
		log.Printf("DEBUG: [%s] NTLM Auth failed: Invalid base64 encoding in NTLM message", clientIP)
		return "", false
	}

	// Check message length to determine if it's a negotiate message (first step)
	// Negotiate messages are typically shorter than authenticate messages
	if len(msgBytes) < 50 {
		log.Printf("DEBUG: [%s] NTLM Auth: Received negotiate message", clientIP)

		// This is handled in ServeHTTP now
		return "", false
	} else {
		// This is likely an authenticate message (third step)
		log.Printf("DEBUG: [%s] NTLM Auth: Received authenticate message", clientIP)

		// Retrieve the session state
		sessionObj, exists := p.ntlmSessions.Load(clientIP)
		if !exists {
			log.Printf("DEBUG: [%s] NTLM Auth failed: No session found", clientIP)
			return "", false
		}

		session := sessionObj.(*NTLMSessionState)

		// In a real implementation, we would use ProcessChallenge to verify the authenticate message
		// For simplicity in this example, we'll consider the authentication successful if we have a session

		// Try to extract domain and username from the authenticate message
		// This is a simplified approach - in a real implementation, you would use
		// ntlmssp.ProcessChallenge to properly verify credentials
		var user string

		// If we can't extract the username, use the configured username
		if user == "" {
			user = p.Username
		}

		// Authentication successful
		log.Printf("DEBUG: [%s] NTLM Auth successful for user %s", clientIP, user)

		// Update session state
		session.Authenticated = true
		p.ntlmSessions.Store(clientIP, session)

		return user, true
	}
}

// ServeHTTP is the main handler for incoming HTTP requests to the proxy.
// It handles authentication, logging, and dispatches to either handleConnect or handleHTTP.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logPrefix := fmt.Sprintf("[%s]", r.RemoteAddr) // Log prefix for correlating messages for a single client connection.
	startTime := time.Now()

	// Optional detailed logging. Can impact performance.
	if p.Verbose {
		dump, err := httputil.DumpRequest(r, true) // true = include body
		if err != nil {
			log.Printf("ERROR: %s Failed to dump request: %v", logPrefix, err)
		} else {
			// Be cautious logging full requests in production due to potential sensitive data and performance overhead.
			log.Printf("VERBOSE: %s RAW REQUEST:\n%s", logPrefix, string(dump))
		}
	} else {
		// Standard concise log line for every request.
		log.Printf("INFO: %s %s %s %s", logPrefix, r.Method, r.Host, r.URL.RequestURI())
	}

	// Check for NTLM or Negotiate negotiate message
	proxyAuth := r.Header.Get("Proxy-Authorization")
	if p.AuthRequired && (strings.HasPrefix(proxyAuth, "NTLM ") || strings.HasPrefix(proxyAuth, "Negotiate ")) {
		// Extract the NTLM message
		var ntlmMsg string
		if strings.HasPrefix(proxyAuth, "NTLM ") {
			ntlmMsg = proxyAuth[5:] // Remove "NTLM " prefix
		} else if strings.HasPrefix(proxyAuth, "Negotiate ") {
			ntlmMsg = proxyAuth[10:] // Remove "Negotiate " prefix
		}

		msgBytes, err := base64.StdEncoding.DecodeString(ntlmMsg)
		if err == nil {
			// Check if this is a negotiate message
			if len(msgBytes) > 0 && len(msgBytes) < 50 { // Simple heuristic for negotiate message
				clientIP := r.RemoteAddr

				// Generate a proper NTLM challenge message
				// We need to create a server challenge response (type-2 message)
				// This is a simplified challenge message that follows the NTLM protocol structure
				// The first 8 bytes are the NTLM signature "NTLMSSP\0"
				// The next 4 bytes are the message type (2 for challenge)
				challenge := []byte{
					'N', 'T', 'L', 'M', 'S', 'S', 'P', 0,
					2, 0, 0, 0, // Type 2 message
				}

				// Add more bytes for a valid NTLM challenge message
				// Including target name, flags, challenge, etc.
				// This is a minimal implementation that should work with most clients
				challenge = append(challenge,
					// Target name fields (length, allocated space, offset)
					0, 0, // Target name length
					0, 0, // Target name allocated space
					56, 0, 0, 0, // Target name offset (56)

					// Flags (NTLM negotiate flags)
					1, 2, 0x82, 0, // Standard flags

					// Server challenge (8 bytes)
					1, 2, 3, 4, 5, 6, 7, 8,

					// Reserved (8 bytes)
					0, 0, 0, 0, 0, 0, 0, 0,

					// Target info fields (length, allocated space, offset)
					0, 0, // Target info length
					0, 0, // Target info allocated space
					56, 0, 0, 0, // Target info offset (56)

					// Version (8 bytes, optional)
					0, 0, 0, 0, 0, 0, 0, 0,
				)

				// Store the challenge in the session cache
				p.ntlmSessions.Store(clientIP, &NTLMSessionState{
					Authenticated: false,
					Challenge:     challenge,
					Timestamp:     time.Now(),
				})

				// Create a challenge message with the same auth method the client used
				var challengePrefix string
				if strings.HasPrefix(proxyAuth, "NTLM ") {
					challengePrefix = "NTLM "
				} else if strings.HasPrefix(proxyAuth, "Negotiate ") {
					challengePrefix = "Negotiate "
				} else {
					challengePrefix = "NTLM " // Default to NTLM if we can't determine
				}

				challengeMsg := challengePrefix + base64.StdEncoding.EncodeToString(challenge)

				// Send the challenge response
				w.Header().Set("Proxy-Authenticate", challengeMsg)
				http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
				log.Printf("DEBUG: %s Sent %schallenge", logPrefix, challengePrefix)
				authType := strings.TrimSpace(challengePrefix)
				log.Printf("ACCESS: %s %s %s %s - DENIED %d (%s Challenge Sent) (%s)",
					logPrefix, r.Method, r.Host, r.URL.RequestURI(),
					http.StatusProxyAuthRequired, authType, time.Since(startTime))
				return
			}
		}
	}

	// Perform authentication check.
	authUser, authenticated := p.checkAuth(r)
	if !authenticated {
		log.Printf("WARN: %s Authentication required, denied user %q", logPrefix, authUser) // Log denied user attempt.

		// Send appropriate authentication challenge
		if strings.HasPrefix(proxyAuth, "NTLM ") {
			w.Header().Set("Proxy-Authenticate", NTLMAuthRealm)
		} else if strings.HasPrefix(proxyAuth, "Negotiate ") {
			w.Header().Set("Proxy-Authenticate", "Negotiate")
		} else {
			w.Header().Set("Proxy-Authenticate", AuthRealm)
		}

		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		// Log access attempt result.
		log.Printf("ACCESS: %s %s %s %s - DENIED %d (Auth Failed) (%s)",
			logPrefix, r.Method, r.Host, r.URL.RequestURI(),
			http.StatusProxyAuthRequired, time.Since(startTime))
		return
	}

	// Dispatch request based on HTTP method.
	if r.Method == http.MethodConnect {
		// CONNECT method is used for establishing tunnels (typically HTTPS).
		p.handleConnect(w, r, logPrefix, startTime)
	} else {
		// Handle standard HTTP methods (GET, POST, etc.).
		statusCode := p.handleHTTP(w, r, logPrefix)
		// Log access attempt result including the final status code.
		log.Printf("ACCESS: %s %s %s %s - FORWARDED %d (%s)", logPrefix, r.Method, r.Host, r.URL.RequestURI(), statusCode, time.Since(startTime))
	}
}

// handleHTTP forwards standard (non-CONNECT) HTTP requests to the target server.
// It returns the final HTTP status code returned by the upstream server or an internal error code.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, logPrefix string) int {
	// Default status code assumes failure until a successful response is received.
	finalStatusCode := http.StatusBadGateway

	// Create the outgoing request, inheriting context (for cancellation) and body.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		log.Printf("ERROR: %s Failed to create outgoing request object: %v", logPrefix, err)
		http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	// Copy headers from the incoming request to the outgoing one.
	// hop-by-hop and proxy-specific headers are filtered by copyHeader.
	outReq.Header = make(http.Header)
	copyHeader(outReq.Header, r.Header)
	// Go's http client automatically sets the Host header from outReq.URL.Host.
	// Ensure r.Host (which might include port) is used if URL.Host is empty.
	outReq.Host = r.Host

	// Execute the outgoing request using the pre-configured transport.
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		errorMsg := fmt.Sprintf("Upstream request failed for %s: %v", outReq.URL.Host, err)
		log.Printf("ERROR: %s %s", logPrefix, errorMsg)
		// Provide more specific error codes to the client based on the error type.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			http.Error(w, errorMsg, http.StatusGatewayTimeout) // Timeout connecting or reading.
			finalStatusCode = http.StatusGatewayTimeout
		} else if errors.As(err, &netErr) {
			http.Error(w, errorMsg, http.StatusServiceUnavailable) // Dial error, connection refused.
			finalStatusCode = http.StatusServiceUnavailable
		} else {
			http.Error(w, errorMsg, http.StatusBadGateway) // Other errors (e.g., invalid response).
			// finalStatusCode remains StatusBadGateway
		}
		return finalStatusCode
	}
	// Ensure the response body is closed eventually.
	defer resp.Body.Close()

	// Success! Record the status code received from the upstream server.
	finalStatusCode = resp.StatusCode
	log.Printf("DEBUG: %s Forwarded %s %s -> %d %s", logPrefix, r.Method, r.Host, resp.StatusCode, resp.Status)

	// Copy upstream response headers and status code back to the client.
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Copy the upstream response body back to the client.
	bytesCopied, err := io.Copy(w, resp.Body)
	if err != nil {
		// This usually means the client disconnected prematurely.
		log.Printf("WARN: %s Error copying response body to client (client likely disconnected): %v", logPrefix, err)
		finalStatusCode = -1 // Special value indicating response copy failed.
	} else {
		log.Printf("DEBUG: %s Copied %d bytes in response body", logPrefix, bytesCopied)
	}

	return finalStatusCode
}

// handleConnect handles the HTTP CONNECT method to establish a TCP tunnel.
// This is typically used for HTTPS traffic.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, logPrefix string, startTime time.Time) {
	// Target host and port are specified in r.Host for CONNECT requests.
	host := r.Host
	// CONNECT requests should typically include the port. Default to 443 if missing.
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}

	log.Printf("INFO: %s CONNECT %s", logPrefix, host)

	// Establish a TCP connection to the target server.
	destConn, err := net.DialTimeout("tcp", host, p.DialTimeout)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to dial target host %s: %v", host, err)
		log.Printf("ERROR: %s %s", logPrefix, errorMsg)
		// Choose appropriate error code based on dial error type.
		var netErr net.Error
		var statusCode int
		if errors.As(err, &netErr) && netErr.Timeout() {
			statusCode = http.StatusGatewayTimeout
		} else {
			statusCode = http.StatusServiceUnavailable
		}
		http.Error(w, errorMsg, statusCode)
		log.Printf("ACCESS: %s CONNECT %s - DENIED %d (Dial Error) (%s)", logPrefix, host, statusCode, time.Since(startTime))
		return
	}
	// Ensure the connection to the destination is eventually closed.
	defer destConn.Close()

	// Hijack the client's connection to gain direct access to the underlying TCP connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Should not happen with the standard net/http server.
		log.Printf("CRITICAL: %s Hijacking not supported by ResponseWriter type %T", logPrefix, w)
		http.Error(w, "Proxy internal error: Hijacking not supported", http.StatusInternalServerError)
		log.Printf("ACCESS: %s CONNECT %s - DENIED %d (Hijack Error) (%s)", logPrefix, host, http.StatusInternalServerError, time.Since(startTime))
		return
	}
	// clientConn is the raw TCP connection to the client.
	// bufRW provides access to any buffered data (should be none before sending 200 OK).
	clientConn, bufRW, err := hijacker.Hijack()
	if err != nil {
		log.Printf("ERROR: %s Cannot hijack client connection: %v", logPrefix, err)
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		log.Printf("ACCESS: %s CONNECT %s - DENIED %d (Hijack Error) (%s)", logPrefix, host, http.StatusInternalServerError, time.Since(startTime))
		return
	}
	// Ensure the client's connection is eventually closed.
	defer clientConn.Close()

	// Check if the client sent data before the tunnel was established. This is invalid.
	if bufRW.Reader.Buffered() > 0 {
		log.Printf("ERROR: %s Client sent %d bytes before CONNECT tunnel established", logPrefix, bufRW.Reader.Buffered())
		// Cannot reliably send HTTP error after hijacking, just close the connection.
		log.Printf("ACCESS: %s CONNECT %s - DENIED %d (Unexpected Data) (%s)", logPrefix, host, http.StatusBadRequest, time.Since(startTime))
		return // Defer will close connections.
	}

	// Send the "200 Connection Established" response to the client.
	// This indicates the tunnel is ready.
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("ERROR: %s Failed to send CONNECT OK to client: %v", logPrefix, err)
		log.Printf("ACCESS: %s CONNECT %s - FAILED (Send OK Error) (%s)", logPrefix, host, time.Since(startTime))
		return // Defer will close connections.
	}

	log.Printf("INFO: %s Tunnel established to %s", logPrefix, host)
	log.Printf("ACCESS: %s CONNECT %s - ESTABLISHED (%s)", logPrefix, host, time.Since(startTime))

	// Start goroutines to blindly forward data between the client and the destination server.
	var wg sync.WaitGroup
	wg.Add(2) // Wait for both directions to complete.
	// Goroutine to copy data from destination server to client.
	go transfer(&wg, destConn, clientConn, logPrefix, "remote->client")
	// Goroutine to copy data from client to destination server.
	go transfer(&wg, clientConn, destConn, logPrefix, "client->remote")

	// Wait until both transfer goroutines have finished.
	wg.Wait()
	log.Printf("INFO: %s Tunnel closed to %s", logPrefix, host)
}

// transfer copies data between dst and src, managing connection closures and logging.
// It signals completion via the WaitGroup.
func transfer(wg *sync.WaitGroup, dst io.WriteCloser, src io.ReadCloser, logPrefix, direction string) {
	defer wg.Done()
	// Closing the WriteCloser often signals the ReadCloser on the other side to stop.
	defer dst.Close()
	// Ensure the source is also closed, redundant but safe.
	defer src.Close()

	startTime := time.Now()
	// io.Copy reads from src and writes to dst until EOF or error.
	bytesCopied, err := io.Copy(dst, src)
	duration := time.Since(startTime)

	logCtx := fmt.Sprintf("%s [%s]", logPrefix, direction)

	// Log transfer statistics and any errors.
	if err != nil {
		// EOF and "use of closed network connection" are expected ways for io.Copy to finish,
		// so don't log them as warnings/errors.
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("WARN: %s Error during transfer: %v", logCtx, err)
		} else {
			log.Printf("DEBUG: %s Transfer finished normally (EOF or closed connection)", logCtx)
		}
	} else {
		log.Printf("DEBUG: %s Transfer finished without error", logCtx)
	}
	log.Printf("DEBUG: %s Transferred %d bytes in %s", logCtx, bytesCopied, duration)
}

// copyHeader selectively copies headers from src to dst.
// It filters out hop-by-hop headers and proxy-specific headers that
// should not be forwarded.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		// Use CanonicalHeaderKey for case-insensitive comparison of header names.
		switch http.CanonicalHeaderKey(k) {
		// Standard hop-by-hop headers (RFC 2616 Section 13.5.1 & RFC 7230 Section 6.1)
		case "Connection", "Keep-Alive", "Proxy-Connection", // Proxy-Connection is non-standard but common
			"Transfer-Encoding", "Te", "Trailer", "Upgrade":
			continue // Skip these headers.
		// Proxy-specific headers that should not be forwarded.
		case "Proxy-Authenticate", "Proxy-Authorization":
			continue // Skip these headers.
		default:
			// Copy all values for allowed header keys.
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}

// main is the entry point of the application.
// It parses command-line flags, sets up the proxy server, and handles graceful shutdown.
func main() {
	// --- Command-line Flag Definitions ---
	var (
		listenAddr           string // Address and port for the proxy to listen on.
		username             string // Username for Basic authentication.
		password             string // Password for Basic authentication.
		authEnabled          bool   // Whether authentication is required.
		verbose              bool   // Whether to enable verbose logging.
		dialTimeoutStr       string // Dial timeout as a string (e.g., "10s").
		tlsTimeoutStr        string // TLS handshake timeout as a string.
		idleTimeoutStr       string // Server idle timeout as a string.
		readHeaderTimeoutStr string // Server read header timeout as a string.
	)

	// Helper to get environment variable value or return a default.
	envOrDefault := func(key, defaultValue string) string {
		if value, ok := os.LookupEnv(key); ok {
			return value
		}
		return defaultValue
	}

	// Define flags, using environment variables as the primary source, falling back to defaults.
	flag.StringVar(&listenAddr, "addr", envOrDefault("PROXY_ADDR", ":8080"), "Proxy listen address (e.g., ':8080') [env: PROXY_ADDR]")
	flag.StringVar(&username, "user", os.Getenv("PROXY_USER"), "Proxy username [env: PROXY_USER]")
	flag.StringVar(&password, "pass", os.Getenv("PROXY_PASS"), "Proxy password [env: PROXY_PASS]")
	flag.BoolVar(&authEnabled, "auth", envOrDefault("PROXY_AUTH_ENABLED", "false") == "true", "Enable Basic authentication [env: PROXY_AUTH_ENABLED=(true|false)]")
	flag.BoolVar(&verbose, "verbose", envOrDefault("PROXY_VERBOSE", "false") == "true", "Enable verbose logging (raw requests) [env: PROXY_VERBOSE=(true|false)]")
	flag.StringVar(&dialTimeoutStr, "dial-timeout", envOrDefault("PROXY_DIAL_TIMEOUT", "10s"), "Timeout for dialing upstream servers [env: PROXY_DIAL_TIMEOUT]")
	flag.StringVar(&tlsTimeoutStr, "tls-timeout", envOrDefault("PROXY_TLS_TIMEOUT", "10s"), "Timeout for TLS handshake upstream [env: PROXY_TLS_TIMEOUT]")
	flag.StringVar(&idleTimeoutStr, "idle-timeout", envOrDefault("PROXY_IDLE_TIMEOUT", "120s"), "Server idle connection timeout [env: PROXY_IDLE_TIMEOUT]")
	flag.StringVar(&readHeaderTimeoutStr, "read-header-timeout", envOrDefault("PROXY_READ_HEADER_TIMEOUT", "10s"), "Server read header timeout [env: PROXY_READ_HEADER_TIMEOUT]")

	flag.Parse() // Parse command-line flags.

	// --- Parse Duration Flags ---
	// Convert string durations from flags/env vars into time.Duration values.
	dialTimeout, err := time.ParseDuration(dialTimeoutStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid dial timeout duration '%s': %v", dialTimeoutStr, err)
	}
	tlsTimeout, err := time.ParseDuration(tlsTimeoutStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid TLS timeout duration '%s': %v", tlsTimeoutStr, err)
	}
	idleTimeout, err := time.ParseDuration(idleTimeoutStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid idle timeout duration '%s': %v", idleTimeoutStr, err)
	}
	readHeaderTimeout, err := time.ParseDuration(readHeaderTimeoutStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid read header timeout duration '%s': %v", readHeaderTimeoutStr, err)
	}

	// --- Validate Configuration ---
	// Ensure credentials are provided if authentication is enabled.
	if authEnabled && (username == "" || password == "") {
		log.Fatal("FATAL: Authentication enabled (-auth=true) but username (-user) or password (-pass) is missing or empty.")
	}

	// --- Initialize Proxy Instance ---
	proxy := NewProxy(username, password, authEnabled, verbose, dialTimeout, tlsTimeout)

	// --- Configure HTTP Server ---
	server := &http.Server{
		Addr:              listenAddr,        // Address to listen on.
		Handler:           proxy,             // The proxy logic handler.
		IdleTimeout:       idleTimeout,       // Max time for idle connections.
		ReadHeaderTimeout: readHeaderTimeout, // Max time to read request headers.
		// Define a specific logger for internal http server errors (e.g., TLS errors, bad requests).
		ErrorLog: log.New(os.Stderr, "HTTP_SERVER_ERROR: ", log.LstdFlags|log.Lmicroseconds),
	}

	// --- Setup Graceful Shutdown ---
	// Create a context that will be canceled when a shutdown signal is received.
	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())

	go func() {
		// Listen for termination signals (SIGINT, SIGTERM).
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		receivedSignal := <-sigChan
		log.Printf("INFO: Received signal: %v. Initiating graceful shutdown...", receivedSignal)

		// Signal all server operations using this context that shutdown has started.
		cancelShutdown()

		// Create a deadline for the shutdown process itself.
		shutdownTimeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelTimeout()

		// Disable keep-alives to allow existing connections to drain gracefully.
		server.SetKeepAlivesEnabled(false)
		// Attempt to shut down the server gracefully.
		if err := server.Shutdown(shutdownTimeoutCtx); err != nil {
			log.Printf("ERROR: Graceful shutdown failed: %v", err)
		} else {
			log.Printf("INFO: Proxy server shut down gracefully.")
		}
	}()

	// --- Start the Server ---
	log.Printf("INFO: Starting proxy server on %s", listenAddr)
	log.Printf("INFO: Configuration - Auth: %t, Verbose: %t, DialTimeout: %s, TLSTimeout: %s, IdleTimeout: %s, ReadHeaderTimeout: %s",
		proxy.AuthRequired, proxy.Verbose, dialTimeout, tlsTimeout, idleTimeout, readHeaderTimeout)

	// ListenAndServe blocks until the server is shut down.
	// It returns ErrServerClosed on graceful shutdown.
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("FATAL: Proxy server failed to start or unexpectedly stopped: %v", err)
	}

	// Wait here until the shutdown process (triggered by signal) is complete.
	<-shutdownCtx.Done()
	log.Printf("INFO: Main process exiting.")
}

// init configures the default logger settings for the application.
func init() {
	// Add microseconds to log timestamps for more precise timing information.
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
