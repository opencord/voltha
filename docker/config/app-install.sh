#!/bin/bash 

for app in $APPS; do
    echo "Installing application '$app'"
    oar=$(find $BUILD_ROOT -path "*/target/*" -name "$app*".oar)
    if [ "$oar x" == " x" ]; then
        echo "Required application, $app, not found."
	continue
    fi
    rm -rf $APP_INSTALL_ROOT
    mkdir -p $APP_INSTALL_ROOT
    cd $APP_INSTALL_ROOT
    cp $oar $APP_INSTALL_ROOT
    jar -xf $APP_INSTALL_ROOT/$(basename $oar)
    name=$(grep "name=" $APP_INSTALL_ROOT/app.xml | sed 's/<app name="//g;s/".*//g')
    mkdir -p $APPS_ROOT/$name
    cp $APP_INSTALL_ROOT/app.xml $APPS_ROOT/$name/app.xml
    touch $APPS_ROOT/$name/active
    [ -f $APP_INSTALL_ROOT/app.png ] && cp $APP_INSTALL_ROOT/app.png $APPS_ROOT/$name/app.png
    cp $APP_INSTALL_ROOT/$(basename $oar) $APPS_ROOT/$name/$name.oar
    cp -rf $APP_INSTALL_ROOT/m2/* $KARAF_M2
    rm -rf $APP_INSTALL_ROOT
done
