
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
