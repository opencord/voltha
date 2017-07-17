#~/bin/bash

rm -fr buildreport
rm vlocate
docker run --rm -v $(pwd):/src -v /var/run/docker.sock:/var/run/docker.sock go-builder $1
sudo chown -R sergio.sergio buildreport
sudo chown sergio.sergio vlocate
