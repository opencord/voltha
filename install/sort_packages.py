#!/usr/bin/env python

# Load the deb_info.txt file into a dictionary for further processing.
deps = dict()
pkgList = list()
sort_list = list()

with open("deb_info.txt") as f:
    for line in f:
        line = line.rstrip("\n")
	linfo=line.split(":")
	pkgList.append(linfo[0])
	deps[linfo[0]]={}
	deps[linfo[0]]["deb_file"] = linfo[1]
	deps[linfo[0]]["deps"] = linfo[2].split(",")


# First extract all packages that don't have any dependencies
# at all with the current set of packages
for key in deps:
    hasDep=False
    #print(key, " has dependencies ", deps[key]["deps"])
    for dep in deps[key]["deps"]:
        if dep in pkgList:
            hasDep=True
    if hasDep == False:
	#print(key, " has no dependencies")
	sort_list.append(key)
	pkgList.remove(key)

for pkg in sort_list:
    print(deps[pkg]["deb_file"])

exit(0)

# The rest is for future layering of updates and
# isn't currently used.

# Now scan iterate over the remaining items and
# add them to the sort_list if they have their
# dependencies satisfied in the sort list.
# Continue until the pkgList is empty
lastLen = 0
while len(pkgList)  > 0:
    p = pkgList
    curLen = len(pkgList)
    if lastLen == curLen:
        for pkg in p:
	    sort_list.append(pkg)
	    pkgList.remove(pkg)
    else:
        lastLen = curLen
    for pkg in p:
        missingDep=False
        for dep in deps[pkg]["deps"]:
            if dep not in sort_list and dep in pkgList:
                missingDep=True
        if missingDep == False:
	    sort_list.append(pkg)
	    pkgList.remove(pkg)
    
# Now write the packages out in the sorted order
# this should ensure that dependent packages are
# installed first.
for pkg in sort_list:
    print(deps[pkg]["deb_file"])
