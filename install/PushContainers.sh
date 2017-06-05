#!/bin/bash

# This script will push all the container images to a registry
# named vinstall:5000

registry="vinstall:5000"

for i in `cat image-list.cfg`
do
docker tag $i $registry/$i
docker push $registry/$i
docker rmi $registry/$i
done


