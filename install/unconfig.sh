#!/bin/bash

# This is a transient development script
# it should be deleted before the final
# upload.

rm -f .ssh/*
sudo rm /etc/sudoers.d/vinstall
sudo apt-get -y remove ansible
sudo apt-get -y autoremove
rm -fr ansible

