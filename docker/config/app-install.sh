touch $APPS/org.onosproject.openflow-base/active

find $ONOS -name "*.oar" -path "*/target/*" | while read line; do 
    mkdir -p $AUX && cd $AUX 
    cp $line $AUX
    jar -xf $AUX/*.oar
    name=$(grep "name=" $AUX/app.xml | sed 's/<app name="//g;s/".*//g')
    mkdir -p $APPS/$name
    cp $AUX/app.xml $APPS/$name/app.xml
    touch $APPS/$name/active
    [ -f $AUX/app.png ] && cp $AUX/app.png $APPS/$name/app.png
    cp $AUX/*.oar $APPS/$name/$name.oar
    cp -rf $AUX/m2/* $KARAF_M2
    rm -fr $AUX
done
