#!/bin/bash

# Ensure log directory exists (since /var/log is mounted)
mkdir -p /var/log/samba

# Check if Samba is already provisioned
if [ ! -f /etc/samba/smb.conf.provisioned ]; then
    echo "Provisioning Domain Controller..."
    
    # Remove default config
    rm /etc/samba/smb.conf
    
    # Provision
    samba-tool domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm=CORP.LOCAL \
        --domain=CORP \
        --adminpass=Admin@123456 \
        --option="dns forwarder = 223.5.5.5"
        
    touch /etc/samba/smb.conf.provisioned
    
    # Copy krb5.conf
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
fi

# Start SSH
service ssh start

# Configure resolv.conf to point to localhost so Samba can find itself
# We back up the original resolv.conf just in case
cp /etc/resolv.conf /etc/resolv.conf.bak
echo "search corp.local" > /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf
# Add a fallback DNS (Aliyun DNS)
echo "nameserver 223.5.5.5" >> /etc/resolv.conf

# Start Samba
# samba -i to run in foreground
exec samba -i
