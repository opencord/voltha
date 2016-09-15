# How to Build and Develop Voltha

There are many ways to build and develop Voltha:

* Use the provided Vagrant environment. This mode is by far the most reliable, and the only one officially supported.
* Use your native MAC OS or Linux environments. These are not supported, although we provide guidance in a best effort manner and contributions/patches are graciously accepted from the community.

## Build and Develop on the Vagrant Box

### Prerequisites

* Git client
* Working installation of Vagrant -- see https://www.vagrantup.com/downloads.html
* jq -- a useful command line too to work with JSON data. On the MAC, you can install jq with ```brew install jq```; on Ubuntu you can do it with ```sudo apt-get install jq```. You will not regret it.


### Build

```
git clone git@bitbucket.org:corddesign/voltha.git
cd voltha
make vagrant
vagrant ssh # the rest to be executed inside the vagrant VM
cd /voltha
make
```

The above has generated a new Docker image '''cord/voltha''' inside the VM. To see it, run:

```
docker images
```

### Run in stand-alone mode

The simplest way to run the image (in the foreground):

```
docker run -ti cord/voltha
```

Unless you happen to have a consul agent running on your local system, you shall see that voltha is trying to connect to a consul agent, without success.

To bring up a consul agent, you can use docker-compose with the provided compose file:

```
docker-compose -f compose/docker-compose-system-test.yml up -d consul
```

This should have started a consul docker container:

```
docker-compose -f compose/docker-compose-system-test.yml ps
```

The above should list the consul conatiner.

To verify that consul is indeed up, you can point your web browser to [http://localhost:8500/ui](http://localhost:8500/ui).
Alternatively, you can use curl to access consul's REST API. For example:

```
curl -s http://localhost:8500/v1/status/leader | jq -r .
```

This should print the IP address (on the docker network) and port number of the internal gossip API for our consul instance (you can ignore the actual data).

Once consul is up, you can extract its IP address programmatically by:

```
CONSUL_IP=`docker inspect compose_consul_1 | \
    jq -r '.[0].NetworkSettings.Networks.compose_default.IPAddress'`
```

With the IP address in hand, you can now start Voltha manually as:

```
docker run -ti --rm --net=compose_default cord/voltha /voltha/main.py --consul=$CONSUL_IP:8500
```

This time it should successfully connect to consul and actually register itself.
You should see a log line simialr to the following:

```
<timestamp> INFO     coordinator.register {name: voltha-1, address: localhost, event: registered-with-consul}
```

To test Voltha's actual service registration with consul, run this (in another terminal):

```
curl -s http://localhost:8500/v1/catalog/service/voltha-1 | jq -r .
```


## Building natively on MAC OS X

For advanced developers this may provide a more comfortable developer
environment (e.g., by allowing IDE-assisted debugging), but setting it up
can be a bit more challenging.

### Prerequisites

* git installed
* Docker-for-Mac installed
* Python 2.7
* virtualenv
* brew (or macports if you prefer)

### Installing Voltha dependencies

The steps that may work (see list of workarounds in case it does not):

```
git clone git@bitbucket.org:corddesign/voltha.git
cd voltha
make venv
```

Potential issues and workaround:

1. Missing virtualenv binary. Resolution: install virtualenv.

   ```
   brew install python pip virtualenv
   ```

1. 'make venv' exits with error 'openssl/opensslv.h': file not found.
   Resolution: install openssl-dev and add a CFLAGS to make venv:

   ```
   brew install openssl
   ```

   Note the version that it installed. For example, '1.0.2h_1'.
   Rerun ```make venv``` as:

   ```
   env CFLAGS="-I /usr/local/Cellar/openssl/1.0.2h_1/include" make venv
   ```

### Building Docker Images and Running Voltha

These steps are not different from the Vagrant path:

```
make
```

Then you shall be able to see the created image and run the container:

```
docker run -ti cord/voltha
```


