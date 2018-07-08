#!/usr/bin/env python
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

"""
Setup grafana with proper datasource and some initial dashboards
"""
import os
from os.path import join as pjoin
import requests
from simplejson import dumps

username = 'admin'
pasword = 'admin'
url = 'http://localhost:8882'
headers = {'content-type': 'application/json'}

def setup_grafana():

    # authenticate to grafana
    session = requests.session()
    login_post = session.post(pjoin(url, 'login'), data=dumps(dict(
        user=username,
        email='',
        password=pasword
    )), headers=headers)
    assert login_post.ok

    # get current list of data sources
    datasources = session.get(pjoin(url, 'api/datasources')).json()

    # check if we have one called 'voltha'
    has_voltha = bool([ds for ds in datasources if ds['name'] == 'voltha'])

    # if does not have voltha yet, add it
    if not has_voltha:
        res = session.put(pjoin(url, 'api/datasources'), data=dumps(dict(
            name='voltha',
            isDefault=True,
            type='graphite',
            url='http://localhost:8000',
            access='proxy',
            withCredentials=False,
            user='',
            password='',
        )))
        assert res.ok

    # get dashboards
    dashboards = session.get(pjoin(url, 'api/search?query=')).json()

    # for now, just print all dashboards as json
    for dashboard in dashboards:
        content = session.get(
            pjoin(url, 'api/dashboards', dashboard['uri'])).json()
        print '========== Dashboard {} ==========='.format(dashboard['title'])
        print dumps(content, indent=4)

    print


if __name__ == '__main__':
    setup_grafana()
