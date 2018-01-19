## Copyright 2017 Open Networking Foundation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
FROM golang:1.9.2-alpine as builder
MAINTAINER Open Networking Foundation <info@onlab.us>

WORKDIR /go
ADD . /go/src/gerrit.opencord.org/unum
RUN go build -o /build/entry-point gerrit.opencord.org/unum

FROM alpine:3.6
MAINTAINER Open Networking Foundation <info@onlab.us>

COPY --from=builder /build/entry-point /service/entry-point

LABEL org.label-schema.description="Provides cluster management for ONOS" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.url="http://opencord.org" \
      org.label-schema.vcs-url="https://gerrit.opencord.org/#/admin/projects/voltha" \
      org.label-schema.vendor="Open Networking Foundation" \
      org.label-schema.version="1.0.0" \
      org.label-schema.name="unum"

WORKDIR /service
ENTRYPOINT ["/service/entry-point"]

