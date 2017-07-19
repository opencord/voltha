# golang-builder

This is a docker image to build Go projects and docker images. The container will run:
* go vet
* golint
* errcheck
* test with race detector
* coverage reports
* The binary
* Docker image


Reports are generated into the `buildreport/` directory.

It is heavily inspired by:[CenturyLinkLabs golang-builder](https://github.com/CenturyLinkLabs/golang-builder).

## Full qualified package
To build the project with valid package references the Go builder needs to create the `GOPATH` with proper directories. Which directories
these are is not in the Go source code. Options are:

### Canonical Import Path
Go allows you to define it via source code comment, for example:

```
package main // import "github.com/alpe/ci-example-project"
```
See [Canonical import paths](https://golang.org/doc/go1.4#canonicalimports)


### Glide package
The [glide](https://github.com/Masterminds/glide) dependency manager allows you to define the root package of your project in it's `glide.yaml` configuration file.
```yaml
package: github.com/alpe/ci-example
import:
...

```
### Godeps
Same with [Godeps](https://github.com/tools/godep). You can define the full qualified package name in the `Godeps/Godeps.json` file:
```json
{
    "ImportPath": "github.com/alpe/ci-example",
    ...
}
```


### Default path
An alternative would be to provide a *default path* which works for all your projects. See the `build_environment.sh`.

## Dependency management
The `build_environment.sh` would be a good start to look how things are currently implemented. Currently supported are:

* [gpm](https://github.com/pote/gpm) is used for dependency management. This doesn't give you reproducable builds and comes with
other issues. Though a lot of our projects use it therefore I support it until all our projects are migrated.
* Official Go vendoring
* [godep](https://github.com/tools/godep) which does vendoring
* [glide](https://github.com/Masterminds/glide)

## Build local

You'll need a [github token](https://github.com/settings/tokens) that you can pass to the container. It will be persisted in the `.netrc` for [gpm](https://github.com/pote/gpm) to access private github repositories.

* Build new go-builder docker image
~~~bash
docker build --build-arg GITHUB_TOKEN=<your-token> -t go-builder .
~~~

* Run container to build binary and code metrics
~~~bash
docker run --rm \
  -v $(pwd):/src \
  go-builder
~~~

* Run container to build docker image, binary and code metrics
~~~bash
docker run --rm \
  -v $(pwd):/src \
  -v /var/run/docker.sock:/var/run/docker.sock \
  go-builder mytag
~~~


### Other Resources
* Dependency management tools https://github.com/golang/go/wiki/PackageManagementTools
* More details how to build minimal docker images: https://labs.ctl.io/small-docker-images-for-go-apps/
* goclean.sh: https://gist.github.com/hailiang/0f22736320abe6be71ce
