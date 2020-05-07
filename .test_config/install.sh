#! /bin/bash

DIRNAME="$( cd "$(dirname "$0")" ; pwd -P )"
APPARMOR_FILE="/etc/apparmor.d/local/usr.sbin.slapd"
SLAPD_APPARMOR_FILE="/etc/apparmor.d/usr.sbin.slapd"

LC_ALL=C DEBIAN_FRONTEND=noninteractive apt install -y \
    sasl2-bin \
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
    krb5-kdc-ldap \
    krb5-user \
    krb5-kdc \
    krb5-admin-server \
    krb5-config

# PATH TO YOUR HOSTS FILE
ETC_HOSTS=/etc/hosts

# DEFAULT IP FOR HOSTNAME
IP="127.0.0.1"

gzip -d /usr/share/doc/krb5-kdc-ldap/kerberos.schema.gz
cp /usr/share/doc/krb5-kdc-ldap/kerberos.schema /etc/ldap/schema/

if [[ -f "${APPARMOR_FILE}" ]]; 
then
  echo "${DIRNAME}/ r," | sudo tee ${APPARMOR_FILE}
  echo "${DIRNAME}/** rwk," | sudo tee -a ${APPARMOR_FILE}
  echo "${TMPDIR}/ r,"  | sudo tee -a ${APPARMOR_FILE} 
  echo "${TMPDIR}/** rwk,"  | sudo tee -a ${APPARMOR_FILE} 
  
  apparmor_parser -r  ${SLAPD_APPARMOR_FILE}
fi

function addhost() {
    HOSTNAME=$1
    HOSTS_LINE="$IP\t$HOSTNAME"
    if [ -n "$(grep $HOSTNAME /etc/hosts)" ]
        then
            echo "$HOSTNAME already exists : $(grep $HOSTNAME $ETC_HOSTS)"
        else
            echo "Adding $HOSTNAME to your $ETC_HOSTS";
            sudo -- sh -c -e "echo '$HOSTS_LINE' >> /etc/hosts";

            if [ -n "$(grep $HOSTNAME /etc/hosts)" ]
                then
                    echo "$HOSTNAME was added succesfully \n $(grep $HOSTNAME /etc/hosts)";
                else
                    echo "Failed to Add $HOSTNAME, Try again!";
            fi
    fi
}

addhost "example"
addhost "example.com"
