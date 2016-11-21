#!/bin/bash
#
# Copyright 2016 the original author or authors.
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
#

set -e

echo 'Test script...'
echo 'First... Preparing env...'
echo "############################### MAKE FETCH & MAKE ###############################"
vagrant ssh -- -t 'cd /voltha && source env.sh && make fetch && make'
echo 'Now... Smoke test...'
echo "################################## SMOKE TEST ###################################"
vagrant ssh -- -t 'cd /voltha && source env.sh && make smoke-test'
echo 'Now... itest...'
echo "#################################### iTEST ######################################"
vagrant ssh -- -t 'cd /voltha && source env.sh && make itest'
echo 'Now... utest...'
echo "#################################### uTEST ######################################"
vagrant ssh -- -t 'cd /voltha && source env.sh && make utest'
echo 'Now... test...'
echo "#################################### TEST #######################################"
vagrant ssh -- -t 'cd /voltha && source env.sh && make test'
echo 'Done with the test...'
