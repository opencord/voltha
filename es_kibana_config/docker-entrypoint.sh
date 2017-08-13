#!/bin/bash
#wait 90 secs for elastic to be up in cluster mode and then push default voltha indices and dashboards.
sleep 90 && elasticdump --input=kibana.json --output=http://elastic:changeme@elasticsearch:9200/.kibana --type=data
set -e

# Add kibana as command if needed
if [[ "$1" == -* ]]; then
	set -- kibana "$@"
fi

# Run as user "kibana" if the command is "kibana"
if [ "$1" = 'kibana' ]; then
	if [ "$ELASTICSEARCH_URL" ]; then
		sed -ri "s!^(\#\s*)?(elasticsearch\.url:).*!\2 '$ELASTICSEARCH_URL'!" /etc/kibana/kibana.yml
	fi

	set -- gosu kibana tini -- "$@"
fi

exec "$@"
