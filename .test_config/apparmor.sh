#! /bin/bash

DIRNAME="$( cd "$(dirname "$0")" ; pwd -P )"
APPARMOR_FILE="/etc/apparmor.d/local/usr.sbin.slapd"
SLAPD_APPARMOR_FILE="/etc/apparmor.d/usr.sbin.slapd"

echo "${DIRNAME}/ r," | sudo tee ${APPARMOR_FILE}
echo "${DIRNAME}/** rwk," | sudo tee -a ${APPARMOR_FILE}
echo "${TMPDIR}/ r,"  | sudo tee -a ${APPARMOR_FILE} 
echo "${TMPDIR}/** rwk,"  | sudo tee -a ${APPARMOR_FILE} q

sudo apparmor_parser -r  ${SLAPD_APPARMOR_FILE}