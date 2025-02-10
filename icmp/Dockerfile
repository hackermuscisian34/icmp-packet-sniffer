# Use an official lightweight Linux image
FROM ubuntu:latest

# Update packages and install necessary tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    iputils-ping \
    python3 \
    python3-pip \
    python3-venv

# Create a virtual environment and install Scapy
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install scapy

# Copy the Python script to the container
COPY icmp_sniffer.py /icmp_sniffer.py

# Set execution permissions
RUN chmod +x /icmp_sniffer.py

# Use the virtual environment when running the script
ENTRYPOINT ["/opt/venv/bin/python", "/icmp_sniffer.py"]
