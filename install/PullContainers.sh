#/bin/bash

# This script will pull all the required docker conatiners
# from the insecure repository.

registry="vinstall:5000"

for i in `cat image-list.cfg`
do
docker pull $registry/$i
docker tag $registry/$i $i
docker rmi $registry/$i
done
