#! /bin/bash

DIRNAME="$( cd "$(dirname "$0")" ; pwd -P )"
APPARMOR_FILE="/etc/apparmor.d/local/usr.sbin.slapd"
SLAPD_APPARMOR_FILE="/etc/apparmor.d/usr.sbin.slapd"

LC_ALL=C DEBIAN_FRONTEND=noninteractive apt install -y \
    sasl2-bin \
    ca-certificates \
    curl \
    ca-certificates \
    curl \
    ldap-utils \
    libsasl2-2 \
    libsasl2-modules \
    libsasl2-modules-db \
    libsasl2-modules-gssapi-mit \
    libsasl2-modules-ldap \
    libsasl2-modules-otp \
    libsasl2-modules-sql \
    openssl \
    slapd \
    krb5-kdc-ldap

if [ -f "${APPARMOR_FILE}" ]; 
then
  echo "${DIRNAME}/ r," | sudo tee ${APPARMOR_FILE}
  echo "${DIRNAME}/** rwk," | sudo tee -a ${APPARMOR_FILE}
  echo "${TMPDIR}/ r,"  | sudo tee -a ${APPARMOR_FILE} 
  echo "${TMPDIR}/** rwk,"  | sudo tee -a ${APPARMOR_FILE} 
  
  apparmor_parser -r  ${SLAPD_APPARMOR_FILE}
fi
