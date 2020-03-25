#! /bin/bash
DIRNAME="$( cd "$(dirname "$0")" ; pwd -P )"
TMPDIR="/tmp/slapd"
LDAPI_PATH="%2Ftmp%2Fslapd%2Fslapdunix"

if [ ! -d "${TMPDIR}" ]
then
  mkdir -p "${TMPDIR}"
else
  rm -rf "${TMPDIR}"
  mkdir -p "${TMPDIR}"
fi

slapd -f "${DIRNAME}/slapd.linux.conf" -h "ldap://localhost:4389/ ldaps://localhost:4636/ ldapi://${LDAPI_PATH}" -d 256 &
sleep 6
ldapadd -h localhost:4389 -D cn=admin,dc=example,dc=com -w test -f "${DIRNAME}/base.ldif"