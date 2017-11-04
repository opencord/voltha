echo "ALL YOUR ENVIRONMENTS BELONG TO US"
curl -sSL get.docker.io | sudo CHANNEL=stable bash
sudo usermod -aG docker $(id -un) 
sudo docker version
groups
sudo grep docker /etc/group
newgrp
groups
ls -ld /var/run/docker.sock
docker version
