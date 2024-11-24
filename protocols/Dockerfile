# Use a Python base image
FROM python:3.8-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    python3-tk \
    tshark \
    sudo \
    libcap2-bin \
    tcpreplay \
    iproute2 \
    && apt-get clean

# Grant permissions to dumpcap for non-root users
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Create a user to run commands
RUN groupadd -r wireshark && useradd -r -g wireshark -m pyshark_user
RUN usermod -aG wireshark pyshark_user
RUN echo "pyshark_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to non-root user
USER pyshark_user

# Install Python dependencies globally
RUN pip install --no-cache-dir pyshark matplotlib

# Set MTU for eth0 and start with a bash shell
CMD ["bash", "-c", "sudo ip link set dev eth0 mtu 3000 && bash"]
