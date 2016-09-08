FROM alpine:3.1

# Update to have latest images
RUN apk add --update python py-pip

# Install app dependencies
RUN apk add build-base gcc abuild binutils python-dev && \
    pip install scapy twisted

# Bundle app source
COPY voltha /voltha

# Exposing process and default entry point
# EXPOSE 8000
CMD ["python", "voltha/voltha.py"]

