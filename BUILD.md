# How to Build and Develop Voltha

There are many ways to build and develop Voltha:

* Use the provided Vagrant environment. This mode is by far the most reliable, and the only one officially supported.
* Use your native MAC OS or Linux environments. These are not supported, although we provide guidance in a best effort manner and contributions/patches are graciously accepted from the community.

## Build and Develop on the Vagrant Box

### Prerequisites

* Git client
* Working installation of Vagrant

### Build

```
git clone git@bitbucket.org:corddesign/voltha.git
cd voltha
make vagrant
vagrant ssh # the rest to be executed inside the vagrant VM
cd /voltha
make
```

The above has generated a new Docker image '''cord/voltha''' inside the VM:

```
docker images
```

### Run in stand-alone (solo) mode

The simplest way to run the image (in the foreground):

```
docker run -ti cord/voltha
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


