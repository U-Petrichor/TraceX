FROM zeek/zeek:latest

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Reset entrypoint from base image
ENTRYPOINT []

# Change to Aliyun mirrors for speed and reliability
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# Install basic tools and services
RUN apt-get update && apt-get install -y \
    openssh-server \
    auditd \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    wget \
    vim \
    nano \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd
# Set root password for simulation (weak password as per guide for testing)
RUN echo 'root:123456' | chpasswd
# Allow root login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Configure Auditd (Basic rules)
COPY audit.rules /etc/audit/rules.d/audit.rules

# Create a non-root user
RUN useradd -m -s /bin/bash user && \
    echo 'user:password' | chpasswd

# Expose SSH port
EXPOSE 22

# Start script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
