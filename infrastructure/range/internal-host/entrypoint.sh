#!/bin/bash

# Start auditd
service auditd start

# Start SSH
/usr/sbin/sshd -D
