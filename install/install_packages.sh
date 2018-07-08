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

pushd /home/voltha

# Find all non-dpendency packages
./sort_packages.sh

# Split the package lists into those that have dependencies and those that don't
mv deb_files{,2}
mkdir deb_files1

# Move all no-dependency packages into the phase 1 directory
for i in `cat sortedDebs.txt`
do
	mv deb_files2/$i deb_files1
done


# Now install the phase 1 packages

sudo dpkg -R -i deb_files1 2>&1 > install.log
sudo apt-get -f install 2>&1 >> install.log
sudo dpkg -R -i deb_files2 2>&1 >> install.log
sudo apt-get -f install 2>&1 >> install.log

rm -f sortedDebs.txt

popd
exit 0
