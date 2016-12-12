#!/usr/bin/env python

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
