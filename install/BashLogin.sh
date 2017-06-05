#!/bin/bash


echo "vinstall ALL=(ALL) NOPASSWD:ALL" > tmp
sudo chown root.root tmp
sudo mv tmp /etc/sudoers.d/vinstall
mkdir .ssh
chmod 0700 .ssh
ssh-keygen -f /home/vinstall/.ssh/id_rsa -t rsa -N ''
