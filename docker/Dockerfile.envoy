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

FROM lyft/envoy:29361deae91575a1d46c7a21e913f19e75622ebe

RUN apt-get update && apt-get -q install -y \
    curl
COPY envoy/front-proxy /envoy/
COPY envoy/proto.pb /envoy/
COPY pki /envoy/
COPY envoy/go/envoyd/envoyd /usr/local/bin

CMD /usr/local/bin/envoy -c /envoy/front-proxy/voltha-grpc-proxy.json
