# Use the official Go image as a parent image
FROM golang:1.19-alpine

# Set the working directory to /app
WORKDIR /app

# Copy the Go modules and download the dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code from the current directory to the /app directory
COPY . .

# Build the Go app
RUN go build -o /scanner ./go/services/scanner

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/scanner"]
