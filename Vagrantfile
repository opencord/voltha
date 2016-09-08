# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  if (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil
    config.vm.synced_folder ".", "/voltha", mount_options: ["dmode=700,fmode=600"]
  else
    config.vm.synced_folder ".", "/voltha"
  end

  config.vm.define "voltha" do |d|
    d.ssh.forward_agent = true
    d.vm.box = "ubuntu/trusty64"
    d.vm.hostname = "voltha"
    d.vm.network "private_network", ip: "10.100.198.220"
    d.vm.provision :shell, path: "ansible/scripts/bootstrap_ansible.sh"
    d.vm.provision :shell, inline: "PYTHONUNBUFFERED=1 ansible-playbook /voltha/ansible/voltha.yml -c local"
    d.vm.provider "virtualbox" do |v|
      v.memory = 2048
    end
  end

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

end
