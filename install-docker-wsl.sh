#!/usr/bin/env bash
# One-off Docker Engine install for the Ubuntu 26.04 WSL distro.
# Uses Docker's `noble` (24.04) apt repo because 26.04 codename `resolute`
# is too new for upstream to publish yet. Run as: `sudo bash install-docker-wsl.sh`.
set -euo pipefail

# DNS in WSL is forwarded through the host and can flake. Add public resolvers
# for the duration of the install (resolv.conf is regenerated on WSL boot).
grep -q "1.1.1.1" /etc/resolv.conf || {
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
}

rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

ARCH="$(dpkg --print-architecture)"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
    > /etc/apt/sources.list.d/docker.list

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin

usermod -aG docker tovsa
systemctl enable --now docker

docker --version
systemctl is-active docker
echo "DONE — log out + back in for docker group to take effect."
