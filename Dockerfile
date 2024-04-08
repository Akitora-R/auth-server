# Use the official Go image as the build environment
FROM golang:1.22.2 as builder

ENV GO111MODULE=on
ENV GOPROXY="https://goproxy.io,direct"

# Set the working directory
WORKDIR /app

# Copy the go module and sum files
COPY go.mod ./
COPY go.sum ./

# Download dependencies
RUN go mod download

# Copy the project files into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-server .

# Use scratch as the final base image to create a minimal container
FROM alpine:latest

# Copy the built application from the builder image
COPY --from=builder /app/auth-server .
COPY --from=builder /app/template ./template/
COPY placeholder.jpg .

# Port that the application listens on
EXPOSE 8080

# Run the application
CMD ["./auth-server"]
