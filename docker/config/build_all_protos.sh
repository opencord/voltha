#!/bin/bash

for i in *.proto; do
    echo -n "Building $i ... "
    /usr/bin/python -m grpc.tools.protoc \
	       $* \
               -I. \
               --python_out=. \
               --grpc_python_out=. \
               --descriptor_set_out=$(basename $i).desc \
               --include_imports \
               --include_source_info \
               $i
    echo "done"
done
