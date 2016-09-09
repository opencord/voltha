FROM alpine:3.1

# Update to have latest images
RUN apk add --update python py-pip

COPY requirements.txt /tmp/requirements.txt

# Install app dependencies
RUN apk add build-base gcc abuild binutils python-dev libffi-dev openssl-dev && \
    pip install -r /tmp/requirements.txt && \
    apk del --purge build-base gcc abuild binutils python-dev libffi-dev openssl-dev

# Bundle app source
COPY voltha /voltha

# Exposing process and default entry point
# EXPOSE 8000
CMD ["python", "voltha/voltha.py"]
