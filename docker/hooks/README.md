# What are these `hook` files?

The files in this directory are levergaed by Docker Cloud (`cloud.docker.com`)
in support of autmatically building VOLTHA containers on the Docker Cloud
infrastructure.

At issue is that for the automated builds Docker Cloud does not set docker
build arguments. You can set environment variables via the automated build UI,
but in order to make these values visible during the building of containers
they must be converted to docker build arguments set via the `--build-arg` 
command line option.

To achieve this a custom *build hook* must be created. This hook will replace
the stardard build command on Docker Cloud and augment the command by setting
build arguments. This is the `build` file in this directory.

Full documentation on *hooks* that can be used with Docker Cloud automated
builds can be found at `https://docs.docker.com/docker-cloud/builds/advanced/`.
