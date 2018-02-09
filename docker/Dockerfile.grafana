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

FROM kamon/grafana_graphite:3.0

MAINTAINER Voltha Community <info@opennetworking.org>

# Update the configuration so grafana runs at a different root
# everything else remains as defined in the kamon version

RUN sed -i~ -e 's~;root_url.*~root_url = /grafana/~' /opt/grafana/conf/custom.ini
