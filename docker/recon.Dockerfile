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
RUN go build -o /recon ./go/services/recon

# Expose port 8081 to the outside world
EXPOSE 8081

# Command to run the executable
CMD ["/recon"]
