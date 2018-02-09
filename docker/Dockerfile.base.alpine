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

FROM alpine:3.6

MAINTAINER Voltha Community <info@opennetworking.org>

# Update to have latest images
RUN apk add --update python py-pip && \
    apk --allow-untrusted --no-cache -X http://apkproxy.heroku.com/andyshinn/alpine-pkg-glibc add glibc glibc-bin

COPY requirements.txt /tmp/requirements.txt

# Install app dependencies
RUN apk add build-base gcc abuild binutils python-dev libffi-dev openssl-dev git linux-headers && \
    pip install cython==0.24.1 enum34 six && \
    pip install -r /tmp/requirements.txt && \
    apk del --purge build-base gcc abuild binutils python-dev libffi-dev openssl-dev git linux-headers

# Bundle app source
COPY voltha /voltha

# Exposing process and default entry point
# EXPOSE 8000
CMD ["python", "voltha/main.py"]
