#! /bin/bash
DIRNAME="$( cd "$(dirname "$0")" ; pwd -P )"
TMPDIR="/tmp/slapd"

if [ ! -d "${TMPDIR}" ]
then
  mkdir -p "${TMPDIR}"
fi

slapd -f "${DIRNAME}/slapd.linux.conf" -h ldap://localhost:4389 -d 4 &
sleep 6
ldapadd -h localhost:4389 -D cn=admin,dc=example,dc=com -w test -f "${DIRNAME}/base.ldif"