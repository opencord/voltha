#!/bin/bash

# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROG=$(basename $0)
BASE_DIR=$(pwd)

usage() {
    echo >&2 "$PROG: [-d <dir>] [-h]"
    echo >&2 "  -d <dir>        directory in which the 'compose file directory' is located, defaults to '$(pwd)'"
    echo >&2 "  -h              this message"
}

OPTIND=1
while getopts d:h OPT; do
    case "$OPT" in
        d) BASE_DIR="$OPTARG";;
        h) usage;
           exit 1;;
        esac
done

for i in $(grep "^\ *image:" $BASE_DIR/compose/*.yml  | awk '{print $3}' | sort -u); do
    eval docker pull $i;
done
