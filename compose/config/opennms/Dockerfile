# Build from latest stable load
FROM opennms/horizon-core-web:19.0.1-1

# Install supervisord
RUN yum install -y python-setuptools
RUN easy_install supervisor
RUN mkdir -p /var/log/supervisor
COPY env/supervisord.conf /etc/supervisor/supervisord.conf

# Copy a new startup script to override the default entrypoint script
COPY env/opennms_start.sh /
RUN chmod 755 /opennms_start.sh

ENTRYPOINT ["/usr/bin/supervisord"]
