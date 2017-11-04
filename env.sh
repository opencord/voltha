echo "ALL YOUR ENVIRONMENTS BELONG TO US"
curl -sSL get.docker.io | sudo CHANNEL=stable bash
sudo usermod -aG docker $(id -un) 
sudo docker version
newgrp docker
docker version
