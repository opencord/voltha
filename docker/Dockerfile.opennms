# Copyright 2018 the original author or authors.
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

# Build from latest stable load
FROM opennms/horizon-core-web:19.0.1-1

# Install supervisord
RUN yum install -y python-setuptools
RUN easy_install supervisor
RUN mkdir -p /var/log/supervisor
RUN mkdir -p /var/log/opennms
RUN mkdir -p /var/opennms/rrd
RUN mkdir -p /var/opennms/reports
COPY compose/opennms/env/supervisord.conf /etc/supervisor/supervisord.conf

# Copy a new startup script to override the default entrypoint script
COPY compose/opennms/env/opennms_start.sh /
RUN chmod 755 /opennms_start.sh

ENTRYPOINT ["/usr/bin/supervisord"]
