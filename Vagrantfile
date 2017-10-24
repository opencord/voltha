# -*- mode: ruby -*-
# vi: set ft=ruby :

require 'yaml'

if ENV['VAGRANT_SETTINGS'] and ENV['VAGRANT_SETTINGS'] != ''
  settings_file = ENV['VAGRANT_SETTINGS']
else
  settings_file = 'settings.vagrant.yaml'
end
puts("Loading vagrant settings from " + settings_file)
settings = YAML.load_file settings_file

Vagrant.configure(2) do |config|

  if /cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM
    puts("Configuring for windows")
    config.vm.synced_folder "../..", "/cord", mount_options: ["dmode=700,fmode=600"]
    Box = "ubuntu/xenial64"
    Provider = "virtualbox"
  elsif RUBY_PLATFORM =~ /linux/
    puts("Configuring for linux")
    if settings['vProvider'] == "virtualbox"
      puts("Using the virtualbox configuration");
      config.vm.synced_folder "../..", "/cord"
      Box = "ubuntu/xenial64"
      Provider = "virtualbox"
    else
      puts("Using the QEMU/KVM configuration");
      Box = "elastic/ubuntu-16.04-x86_64"
      Provider = "libvirt"
      if settings['testMode'] == "true" or settings['installMode'] == "true"
          config.vm.synced_folder ".", "/vagrant", disabled: true
          config.vm.synced_folder "../..", "/cord", type: "rsync", rsync__exclude: [".git", "venv-linux", "install/volthaInstaller", "install/volthaInstaller-2"], rsync__args: ["--verbose", "--archive", "--delete", "-z", "--links"]
      else
          config.vm.synced_folder ".", "/vagrant", rsync__exclude: [".git", "venv-linux", "install/volthaInstaller", "install/volthaInstaller-2"], rsync__args: ["--verbose", "--archive", "--delete", "-z", "--links"]
          config.vm.synced_folder "../..", "/cord", type: "nfs", rsync__exclude: [".git", "venv-linux", "install/volthaInstaller", "install/volthaInstaller-2"], rsync__args: ["--verbose", "--archive", "--delete", "-z", "--links"]
      end
    end
  else
    puts("Configuring for other")
    config.vm.synced_folder "../..", "/cord"
    Box = "ubuntu/xenial64"
    Provider = "virtualbox"
  end

  config.vm.define "#{settings['server_name']}" do |d|
    d.ssh.forward_agent = true
    d.vm.box = Box
    if Box == "ubuntu/xenial64"
        d.vm.box_version = "20170207.0.0"
    end
    d.vm.hostname = "#{settings['server_name']}"
    d.vm.network "private_network", ip: "10.100.198.220"
    d.vm.provision :shell, path: "ansible/scripts/bootstrap_ansible.sh"
    d.vm.provision :shell, inline: "PYTHONUNBUFFERED=1 ansible-playbook /cord/incubator/voltha/ansible/voltha.yml -c local"
    d.vm.provision :shell, inline: "cd /cord/incubator/voltha && source env.sh && make install-protoc && chmod 777 /tmp/fluentd"
    d.vm.provider Provider do |v|
      v.memory = 6144
      v.cpus = 4
      if settings['vProvider'] == "KVM"
          v.cpu_mode = 'host-passthrough'
          v.cpu_fallback = 'allow'
      end
    end
  end

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

end
