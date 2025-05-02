# Go Authentication Proxy

A lightweight HTTP/HTTPS proxy server written in Go with optional Basic Authentication and NTLM Authentication support.

## Features

- Supports HTTP and HTTPS proxying.
- Optional Basic Authentication for enhanced security.
- NTLM and Negotiate Authentication support for Windows-based environments.
- Configurable timeouts for better performance and protection against slow clients.
- Verbose logging for debugging and monitoring.

## Running with Docker

This project includes a `Dockerfile` and `docker-compose.yml` for easy containerization.

### Prerequisites

- Docker: [Install Docker](https://docs.docker.com/get-docker/)
- Docker Compose: [Install Docker Compose](https://docs.docker.com/compose/install/)

### Building and Running with Docker Compose

1. **Navigate to the project directory:**
   ```bash
   cd /path/to/proxy-go
   ```

2. **(Optional) Configure environment variables:**
   Create a `.env` file or export variables directly in your shell. Example:
   ```bash
   export PROXY_USER="my_user"
   export PROXY_PASS="my_password"
   export PROXY_AUTH_ENABLED="true"
   export PROXY_VERBOSE="false"
   ```

   Alternatively, edit the `.env` file provided in the project.

3. **Build and start the proxy:**
   ```bash
   docker-compose up --build -d
   ```

4. **Verify the proxy is running:**
   Check the logs to ensure the proxy started successfully:
   ```bash
   docker-compose logs -f
   ```

5. **Stop the proxy:**
   ```bash
   docker-compose down
   ```

### Using the Proxy

Configure your client to use the proxy at `http://localhost:8080` with the username and password you set.

#### Basic Authentication Example with `curl`:
```bash
curl --proxy-user my_user:my_password -x http://localhost:8080 http://ifconfig.me/ip
```

#### NTLM and Negotiate Authentication:
Most browsers and tools that support NTLM authentication will automatically negotiate the NTLM authentication protocol with the proxy. The proxy server will respond with the appropriate NTLM or Negotiate challenge when it receives an authentication negotiate message.

The proxy supports both the "NTLM" and "Negotiate" authentication methods, allowing it to work with a wider range of clients and authentication scenarios.

For Windows clients, NTLM/Negotiate authentication is often handled automatically by the system when configured to use a proxy that requires NTLM authentication.

#### Example with a browser:
- Set the proxy address to `http://localhost:8080`.
- Enter the username and password when prompted.
- For NTLM or Negotiate authentication, the browser will typically handle the authentication negotiation automatically.

## Configuration

The proxy can be configured using environment variables. Below are the key settings:

| Variable                  | Description                                                                 | Default       |
|---------------------------|-----------------------------------------------------------------------------|---------------|
| `PROXY_ADDR`              | Address and port the proxy listens on.                                     | `:8080`       |
| `PROXY_AUTH_ENABLED`      | Enable or disable Basic Authentication (`true` or `false`).                | `true`        |
| `PROXY_USER`              | Username for Basic Authentication.                                         | `proxyuser`   |
| `PROXY_PASS`              | Password for Basic Authentication.                                         | `proxypass123`|
| `PROXY_VERBOSE`           | Enable verbose logging (`true` or `false`).                                | `false`       |
| `PROXY_DIAL_TIMEOUT`      | Timeout for establishing TCP connections to upstream servers.              | `10s`         |
| `PROXY_TLS_TIMEOUT`       | Timeout for the TLS handshake with upstream HTTPS servers.                 | `10s`         |
| `PROXY_IDLE_TIMEOUT`      | Maximum time the server keeps an idle client connection open.              | `120s`        |
| `PROXY_READ_HEADER_TIMEOUT` | Maximum time to read the headers from a client request.                  | `10s`         |

You can set these variables in the `.env` file or directly in the `docker-compose.yml`.

## Development

To run the proxy locally without Docker:

1. **Install Go:**
   [Install Go](https://golang.org/doc/install) if you don't already have it.

2. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/proxy-go.git
   cd proxy-go
   ```

3. **Run the proxy:**
   ```bash
   go run main.go
   ```

4. **Test the proxy:**
   Use the same instructions as in the "Using the Proxy" section.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

`
