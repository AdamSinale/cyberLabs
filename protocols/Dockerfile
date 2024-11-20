FROM handsonsecurity/seed-ubuntu:large

# Install required packages
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-tk \
    iproute2 \
    xvfb \
    x11-apps

# Install Python dependencies
RUN pip3 install pyshark matplotlib

# Set the working directory
WORKDIR /volumes

# Copy all files into the container
COPY ./volumes /volumes

# Expose port for container GUI apps
EXPOSE 5900

# Default command to keep the container running
CMD ["bash", "-c", "tail -f /dev/null"]
