#!/usr/bin/dumb-init /bin/sh

uid=${FLUENT_UID:-1000}

# check if a old fluent user exists and delete it
cat /etc/passwd | grep fluent
if [ $? -eq 0 ]; then
    deluser fluent
fi

# (re)add the fluent user with $FLUENT_UID
adduser -D -g '' -u ${uid} -h /home/fluent fluent

# chown home and data folder
chown -R fluent /home/fluent
chown -R fluent /fluentd

echo "$WAIT_FOR"
if [ ! -z "$WAIT_FOR" ]; then
  for i in $WAIT_FOR; do
      /bin/wait_for_it.sh -t ${WAIT_FOR_TIMEOUT:-30} $i
  done
fi

exec su-exec fluent "$@"
