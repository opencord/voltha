#!/bin/bash

# licensecheck.sh
# checks for copyright/license headers on files
# excludes filename extensions where this check isn't pertinent

set +e -u -o pipefail
fail_licensecheck=0

while IFS= read -r -d '' f
do
  grep -q "Copyright\|Apache License" "${f}"
  rc=$?
  if [[ $rc != 0 ]]; then
    echo "ERROR: $f does not contain License Header"
    fail_licensecheck=1
  fi
done < <(find . -name ".git" -prune -o -type f \
  -name "*.*" \
  ! -name "*.PNG" \
  ! -name "*.asc" \
  ! -name "*.bat" \
  ! -name "*.cert" \
  ! -name "*.cfg" \
  ! -name "*.cnf" \
  ! -name "*.conf" \
  ! -name "*.cql" \
  ! -name "*.crt" \
  ! -name "*.csar" \
  ! -name "*.csr" \
  ! -name "*.csv" \
  ! -name "*.ctmpl" \
  ! -name "*.curl" \
  ! -name "*.db" \
  ! -name "*.der" \
  ! -name "*.desc" \
  ! -name "*.diff" \
  ! -name "*.dnsmasq" \
  ! -name "*.do" \
  ! -name "*.docx" \
  ! -name "*.eot" \
  ! -name "*.gif" \
  ! -name "*.gpg" \
  ! -name "*.graffle" \
  ! -name "*.groovy" \
  ! -name "*.ico" \
  ! -name "*.iml" \
  ! -name "*.in" \
  ! -name "*.inc" \
  ! -name "*.install" \
  ! -name "*.j2" \
  ! -name "*.jar" \
  ! -name "*.jks" \
  ! -name "*.jpg" \
  ! -name "*.json" \
  ! -name "*.jsonld" \
  ! -name "*.JSON" \
  ! -name "*.key" \
  ! -name "*.list" \
  ! -name "*.local" \
  ! -path "*.lock" \
  ! -name "*.log" \
  ! -name "*.mak" \
  ! -name "*.md" \
  ! -name "*.MF" \
  ! -name "*.mk" \
  ! -name "*.oar" \
  ! -name "*.p12" \
  ! -name "*.patch" \
  ! -name "*.pdf" \
  ! -name "*.pcap" \
  ! -name "*.pem" \
  ! -name "*.png" \
  ! -name "*.properties" \
  ! -name "*.proto" \
  ! -name "*.pyc" \
  ! -name "*.repo" \
  ! -name "*.robot" \
  ! -name "*.rst" \
  ! -name "*.rules" \
  ! -name "*.service" \
  ! -name "*.svg" \
  ! -name "*.swp" \
  ! -name "*.tar" \
  ! -name "*.tar.gz" \
  ! -name "*.toml" \
  ! -name "*.ttf" \
  ! -name "*.txt" \
  ! -name "*.woff" \
  ! -name "*.xproto" \
  ! -name "*.xtarget" \
  ! -name "*ignore" \
  ! -name "nosetests.*" \
  ! -name "*rc" \
  ! -name "Dockerfile" \
  ! -name "Dockerfile.*" \
  ! -name "Makefile" \
  ! -name "Makefile.*" \
  ! -name "coverage.*" \
  ! -name "README" \
  ! -name ".coverage" \
  ! -name "junit-*" \
  ! -path "*/vendor/*.go" \
  ! -path "*nginx_config*" \
  ! -path "*experiments*" \
  ! -path "*netopeer*" \
  ! -path "*compose*" \
  ! -path "*git*" \
  ! -path "*swagger*" \
  ! -path "*venv*" \
  ! -path "*protos*" \
  ! -path "*swagger*" \
  ! -path "*tmp*" \
  ! -path "*htmlcov*" \
  ! -path "*prof*" \
  ! -path "*netconf/*" \
  -print0 )

exit ${fail_licensecheck}
