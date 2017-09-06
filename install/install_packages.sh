#!/bin/bash

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
