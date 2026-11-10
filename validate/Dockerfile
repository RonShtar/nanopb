# Use Ubuntu as base image
FROM ubuntu:22.04

# Install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    gcc \
    g++ \
    python3 \
    python3-pip \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Python protobuf libraries
RUN pip3 install protobuf grpcio-tools

# Set working directory
WORKDIR /workspace

# Copy the nanopb source code
COPY . /workspace/

# Make the generator executable
RUN chmod +x generator/nanopb_generator

# Set environment variables
ENV PYTHONPATH=/workspace/generator

# Default command
CMD ["/bin/bash"]
