#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

""" Rest API to check health of Voltha instance """

from klein import Klein
from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.web.server import Site


class HealthCheck(object):

    app = Klein()

    @app.route('/health')
    def health_check(self, request):
        # TODO this is just a placeholder, very crude health check
        return '{"status": "ok"}'

    def get_site(self):
        return Site(self.app.resource())


def init_rest_service(port):  # TODO need to be moved to a shared file across all resources
    hc = HealthCheck()
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port)
    endpoint.listen(hc.get_site())
