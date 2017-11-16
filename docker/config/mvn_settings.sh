#!/bin/bash
if [ -f mvn_settings.custom.xml ] ; then
  cp mvn_settings.custom.xml mvn_settings.xml
  exit 0
fi

if [ "$http_proxy$https_proxy" != "" ] ; then
  echo "  <proxies>" >> mvn_settings.proxy.xml
  for PROTOCOL in http https ; do
    proxy="${PROTOCOL}_proxy"
    proxy="${!proxy}"
    if [ "$proxy" = "" ] ; then continue ; fi

    # username/password not yet included
    PROXY_HOST=$(echo "$proxy" | sed "s@.*://@@;s/.*@//;s@:.*@@")
    PROXY_PORT=$(echo "$proxy" | sed "s@.*://@@;s@.*:@@;s@/.*@@")
    NON_PROXY=$(echo "$no_proxy" | sed "s@,@|@g")

    echo "   <proxy>
      <id>$PROTOCOL</id>
      <active>true</active>
      <protocol>$PROTOCOL</protocol>
      <host>$PROXY_HOST</host>
      <port>$PROXY_PORT</port>
      <nonProxyHosts>$NON_PROXY</nonProxyHosts>
    </proxy>" >> mvn_settings.proxy.xml
  done
  echo "  </proxies>" >> mvn_settings.proxy.xml

  sed -i '/<!--PROXY-->/r mvn_settings.proxy.xml' mvn_settings.xml
fi

if [ -f mvn_settings.extra.xml ] ; then
  sed -i 's/<!--EXTRA-->/r mvn_settings.extra.xml' mvn_settings.xml
fi
