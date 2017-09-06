#!/bin/bash

debDir="deb_files"

rm -f deb_info.txt
rm -f debFiles.txt
rm -f sortedDebs.txt

# Create the paackage information file for further processing by Python
ls $debDir/*.deb | sed -e 's~deb_files/~~' > debFiles.txt


for i in `cat debFiles.txt`
do
	pkgName=""
	deps=""
	pkgName=`dpkg -I $debDir/$i | egrep "^[ ]*Package:" | sed -e 's/Package://' | sed -e 's/\([ ]\+\)\|\([ ]\+$\)//'`
	deps=`dpkg -I $debDir/$i | grep Depends: | sed -e 's/Depends://' | sed -e 's/\([ ]\+\)\|\([ ]\+$\)//'`
	deps=`echo $deps | sed -e 's/|/,/g' | sed -e 's/([^)]\+)//g' | sed -e 's/:any//g' | sed -e 's/,//g'`
	deps=`echo $deps | sed -e 's/[ ]\+/ /g' |  sed -e 's/\(^[ ]\+\)\|\([ ]\+$\)//' | sed -e 's/ /,/g'`
	#deps=`echo $deps | sed -e 's/^\(.\)/"\1/' | sed -e 's/\(.\)$/\1"/' | sed -s 's/,/","/g'`
	echo "${pkgName}:${i}:${deps}" >> deb_info.txt
done
rm -f debFiles.txt

# Now launch the python scrip that sorts the files based on the dependencies.
./sort_packages.py > sortedDebs.txt

rm -f deb_info.txt
