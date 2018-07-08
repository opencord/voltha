#!/bin/bash
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

tagName=$1

if ( find /src -maxdepth 0 -empty | read v );
then
  echo "Error: Must mount Go source code into /src directory"
  exit 990
fi

# Grab Go package name
pkgName="$(go list -e -f '{{.ImportComment}}' 2>/dev/null || true)"

if [ -z "$pkgName" ];
then
    if [ -f "/src/glide.yaml" ]
    then
        pkgName="$(glide name)"
    elif [ -f "/src/Godeps/Godeps.json" ]
    then
        pkgName="$(cat /src/Godeps/Godeps.json | jq --raw-output '.ImportPath')"
    else
        url=$(git config --get remote.origin.url)
        if [[ "$url" == http* ]]
        then
            pkgName=$(echo ${url} | sed -E 's|https?://(.+)|\1|')
        elif [[ "$url" == git@* ]]
        then
            pkgName=$(echo ${url} | sed -E 's|git@(.+):(.+).git|\1/\2|')
        fi
    fi
fi

if [ -z "$pkgName" ];
then
  echo "Error: Must add canonical import path to root package"
  exit 992
fi

# Grab just first path listed in GOPATH
goPath="${GOPATH%%:*}"

# Construct Go package path
pkgPath="$goPath/src/$pkgName"

# Set-up src directory tree in GOPATH
mkdir -p "$(dirname "$pkgPath")"

# Link source dir into GOPATH
ln -sf /src "$pkgPath"

# change work dir to
cd $pkgPath

echo "--------------------------------------"
echo "* Resolve dependencies"
if [ -e "$pkgPath/vendor" ];
then
    echo "unsing vendor folder"
elif [ -d "$pkgPath/Godeps" ];
then
   gpm install
elif [ -d "$pkgPath/Godeps/_workspace" ];
then
  # Add local godeps dir to GOPATH
  GOPATH=$pkgPath/Godeps/_workspace:$GOPATH
elif [ -f "$pkgPath/glide.yaml" ];
then
    glide install
else
  # Get all package dependencies
  go get -t -d -v ./...
fi
