FROM zeek/zeek:latest

ENV DEBIAN_FRONTEND=noninteractive

# Reset entrypoint from base image
ENTRYPOINT []

# Change to Aliyun mirrors for speed and reliability
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# Install Samba and dependencies for AD DC
RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    winbind \
    libpam-winbind \
    libnss-winbind \
    krb5-config \
    krb5-user \
    openssh-server \
    iproute2 \
    iputils-ping \
    net-tools \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd
RUN echo 'root:123456' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Expose ports for AD DC
# TCP: 53 (DNS), 88 (Kerberos), 135 (RPC), 139 (NetBIOS), 389 (LDAP), 445 (SMB), 464 (Kerberos), 636 (LDAPS), 3268 (GC), 3269 (GC SSL)
# UDP: 53 (DNS), 88 (Kerberos), 137 (NetBIOS), 138 (NetBIOS), 389 (LDAP), 464 (Kerberos)
EXPOSE 53 88 135 139 389 445 464 636 3268 3269
EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
