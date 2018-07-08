#!/bin/bash -e
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source /build_environment.sh

mkdir buildreport
novendor_dirs=$(go list ./... | grep -v '/vendor/')

echo "Using nonvendor dirs:"
echo "$novendor_dirs"
echo "--------------------------------------"

echo "* Run tests with race detector"
go test -race ${novendor_dirs}

echo "--------------------------------------"
echo "* Run vet + golint"
for f in go_vet.txt golint.txt
do
    touch buildreport/${f}
done

for d in $novendor_dirs
do
    go vet ${d} 2>> buildreport/go_vet.txt || true
    golint ${d} >> buildreport/golint.txt || true
done

echo "--------------------------------------"
echo "* Run errcheck"
errcheck ${novendor_dirs} > buildreport/errcheck.txt || true


# Run test coverage on each subdirectories and merge the coverage profile.
echo "--------------------------------------"
echo "* Building coverage report"

echo "mode: count" > buildreport/profile.cov
coverDirs=$novendor_dirs
for dir in $coverDirs
do
    path="$GOPATH/src/$dir"
    if ls $path/*.go &> /dev/null; then
        go test -covermode=count -coverprofile=$path/profile.tmp $dir
        if [ -f $path/profile.tmp ]
        then
            cat $path/profile.tmp | tail -n +2 >> buildreport/profile.cov
            rm $path/profile.tmp
        fi
    fi
done

go tool cover -html buildreport/profile.cov -o buildreport/cover.html

echo "--------------------------------------"
main_packages=$(go list ./... |grep -v vendor |grep cmd || true)
main_packages+=( ${pkgName} )
for pkg in ${main_packages[@]}
do
    # Grab the last segment from the package name
    name=${pkg##*/}
    echo "* Building Go binary: $pkg to goPath/src/$pkg/$name"

    flags=(-a -installsuffix cgo)
    ldflags=('-s -X main.version='$BUILD_VERSION)

    # Compile statically linked version of package
    # see https://golang.org/cmd/link/ for all ldflags
    CGO_ENABLED=${CGO_ENABLED:-0} go build \
        "${flags[@]}" \
        -ldflags "${ldflags[@]}" \
        -o "$goPath/src/$pkg/$name" \
        "$pkg"

    if [[ $COMPRESS_BINARY == "true" ]];
    then
      goupx $name
    fi

    if [ "$OUTPUT X" != " X" ]; then
        echo "* Copy Go Binary to \"$OUTPUT/$name\""
        mkdir -p $OUTPUT
        cp "$goPath/src/$pkg/$name" "$OUTPUT/$name"
    fi

    if [ -e "/var/run/docker.sock" ] && [ -e "$goPath/src/$pkg/Dockerfile" ];
    then

        # Default TAG_NAME to package name if not set explicitly
        tagName=${tagName:-"$name":latest}
        echo "--------------------------------------"
        echo "* Building Docker image: $tagName"

        # Build the image from the Dockerfile in the package directory
        docker build --pull -t $tagName .
    fi
done
