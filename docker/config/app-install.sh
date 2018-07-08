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

HERE=$(pwd)
OARS=$(find $DOWNLOAD_ROOT -name "*.oar")
for oar in $OARS; do
    cd $HERE
    echo "Installing application '$oar'"
    rm -rf $APP_INSTALL_ROOT
    mkdir -p $APP_INSTALL_ROOT
    cd $APP_INSTALL_ROOT
    cp $oar $APP_INSTALL_ROOT
    unzip -oq -d . $APP_INSTALL_ROOT/$(basename $oar)
    name=$(grep "name=" $APP_INSTALL_ROOT/app.xml | sed 's/<app name="//g;s/".*//g')
    mkdir -p $APPS_ROOT/$name
    cp $APP_INSTALL_ROOT/app.xml $APPS_ROOT/$name/app.xml
    touch $APPS_ROOT/$name/active
    [ -f $APP_INSTALL_ROOT/app.png ] && cp $APP_INSTALL_ROOT/app.png $APPS_ROOT/$name/app.png
    cp $APP_INSTALL_ROOT/$(basename $oar) $APPS_ROOT/$name/$name.oar
    cp -rf $APP_INSTALL_ROOT/m2/* $KARAF_M2
    rm -rf $APP_INSTALL_ROOT
done
