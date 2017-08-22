#!/bin/bash 

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
