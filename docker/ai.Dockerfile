# Use the official Python image as a parent image
FROM python:3.10-slim

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file and install the dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code from the current directory to the /app directory
COPY . .

# Command to run the Python application
CMD ["python", "./python/main.py"]
