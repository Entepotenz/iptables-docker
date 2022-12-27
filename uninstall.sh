#!/bin/sh

echo "Disable iptables-docker"

systemctl stop iptables-docker
systemctl disable iptables-docker

systemctl stop ip6tables-docker
systemctl disable ip6tables-docker

echo "remove iptables-docker.sh"

rm -rf /usr/local/sbin/iptables-docker.sh
rm -rf /usr/local/sbin/ip6tables-docker.sh

rm -rf /usr/local/sbin/awk.firewall

echo "remove systemd unit"

rm -rf /etc/systemd/system/iptables-docker.service
rm -rf /etc/systemd/system/ip6tables-docker.service

echo "Reload systemd"

systemctl daemon-reload