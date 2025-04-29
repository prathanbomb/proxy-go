# Build the Go binary
build:
	go build -o proxy main.go

# Run the application locally
run: build
	./proxy

# Run the application with Docker Compose
docker-run:
	docker-compose -f docker/docker-compose.yml up --build -d

# Stop the Docker Compose services
docker-stop:
	docker-compose -f docker/docker-compose.yml down

# Clean up build artifacts
clean:
	rm -f proxy
