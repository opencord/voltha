#!/bin/bash

for i in *.proto; do
    echo -n "Building $i ... "
    /usr/bin/python -m grpc.tools.protoc \
	       $* \
               -I. \
               --python_out=. \
               --grpc_python_out=. \
	       --descriptor_set_out=$(echo $(basename $i) | sed -e 's/\.proto$/\.desc/g') \
               --include_imports \
               --include_source_info \
               $i
    echo "done"
done
