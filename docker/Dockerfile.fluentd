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

#DockerFile to Create Fluentd Forwards inside cord-voltha
FROM fluent/fluentd:v0.12.42
MAINTAINER Voltha Community <info@opennetworking.org>

RUN apk add --update bash
COPY fluentd_config/fluent.conf /fluentd/etc/
COPY fluentd_config/fluent-agg.conf /fluentd/etc/
COPY docker/config/wait_for_it.sh /bin/wait_for_it.sh
COPY fluentd_config/entrypoint.sh /bin/entrypoint.sh
RUN chmod 755 /bin/wait_for_it.sh /bin/entrypoint.sh
