#!/bin/sh
# $Id: alcasar-CA.sh 1705 2015-10-20 16:52:33Z richard $

# alcasar-CA.sh
# by Franck BOUIJOUX, Pascal LEVANT and Richard REY
# This script is distributed under the Gnu General Public License (GPL)
#
# Some ideas from "nessus-mkcert" script written by Renaud Deraison <deraison@cvs.nessus.org> 
# and Michel Arboi <arboi@alussinan.org>
#
DIR_TMP=${TMPDIR-/tmp}/alcasar-mkcert.$$
DIR_PKI=/etc/pki
DIR_CERT=$DIR_PKI/tls
DIR_WEB=/var/www/html
CACERT=$DIR_PKI/CA/alcasar-ca.crt
CAKEY=$DIR_PKI/CA/private/alcasar-ca.key
SRVREQ=$DIR_CERT/alcasar.req
SRVKEY=$DIR_CERT/private/alcasar.key
SRVCERT=$DIR_CERT/certs/alcasar.crt
SRVCHAIN=$DIR_CERT/certs/server-chain.crt

CACERT_LIFETIME="1460"
SRVCERT_LIFETIME="1460"
COUNTRY="FR"
PROVINCE="none"
LOCATION="Paris"
ORGANIZATION="ALCASAR-Team"

mkdir $DIR_TMP || exit 1
# dynamic conf file for openssl
cat <<EOF >$DIR_TMP/ssl.conf
RANDFILE		= $HOME/.rnd
#
[ ca ]
default_ca = AlcasarCA

[ AlcasarCA ]
dir		= $DIR_TMP		# Where everything is kept
certs		= \$dir			# Where the issued certs are kept
crl_dir		= \$dir			# Where the issued crl are kept
database	= \$dir/index.txt	# database index file.
new_certs_dir	= \$dir			# default place for new certs.

certificate	= $CACERT	 	# The CA certificate
serial		= \$dir/serial 		# The current serial number
crl		= \$dir/crl.pem 	# The current CRL
private_key	= $CAKEY		# The private key

x509_extensions	= usr_cert		# The extentions to add to the cert
crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= sha256		# which message digest to use.
preserve	= no			# keep passed DN ordering

policy		= policy_anything

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits		= 2048
distinguished_name	= req_distinguished_name
# attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= FR
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)
localityName_default		= Lyon

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= your organization name

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (eg, your name or your server\'s hostname)
commonName_max			= 255

emailAddress			= Email Address
emailAddress_max		= 255

# SET-ex3			= SET extension number 3

[ usr_cert ]
# These extensions are added when 'ca' signs a request.
# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.
#basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= nsCertType
# For normal client use this is typical
# nsCertType = client, email
nsCertType			= server

keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
subjectAltName=email:copy

# Copy subject details
issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

[ v3_ca ]
# PKIX recommendation.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
basicConstraints = critical,CA:true
# So we do this instead.
#basicConstraints = CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
keyUsage = cRLSign, keyCertSign
nsCertType = sslCA
EOF

hostname=`hostname`
if [ -z "$hostname" ];
then
 echo "Impossible de déterminer le nom d'hôte !!!"
 exit 1
fi

# The value for organizationalUnitName must be 64 chars or less;
#   thus, hostname must be 36 chars or less. If it's too big,
#   try removing domain (merci REXY ;-) ).
hostname_len=`echo $hostname| wc -c`
if [ $hostname_len -gt 36 ];
then
  hostname=`echo $hostname | cut -d '.' -f 1`
fi

CAMAIL=ca@$hostname
SRVMAIL=apache@$hostname

echo 01 > $DIR_TMP/serial
touch $DIR_TMP/index.txt

# CA key
rm -f $CAKEY
echo "*********CAKEY*********" > $DIR_TMP/openssl-log
openssl genrsa -out $CAKEY  2048 2>> $DIR_TMP/openssl-log

# CA certificate
rm -f $CACERT
echo "*********CACERT*********" >> $DIR_TMP/openssl-log
echo "$COUNTRY
$PROVINCE
$LOCATION
$ORGANIZATION
Certification Authority for $hostname
ALCASAR-local-CA
$CAMAIL" | 
openssl req -config $DIR_TMP/ssl.conf -new -x509 -sha256 -days $CACERT_LIFETIME -key $CAKEY -out $CACERT 2>> $DIR_TMP/openssl-log

# Server key
rm -f $SRVKEY	
echo "*********SRVKEY*********" >> $DIR_TMP/openssl-log
openssl genrsa -out $SRVKEY 2048 2>> $DIR_TMP/openssl-log

# Server certificate "request"
echo "*********SRVRQST*********" >> $DIR_TMP/openssl-log
echo "$COUNTRY
$PROVINCE
$LOCATION
$ORGANIZATION
Server certificate for $hostname
$hostname
$SRVMAIL" | 
openssl req -config $DIR_TMP/ssl.conf -new -key $SRVKEY -out $SRVREQ 2>> $DIR_TMP/openssl-log

# Sign the server certificate "request" to create server certificate
rm -f $SRVCERT
echo "*********SRVCERT*********" >> $DIR_TMP/openssl-log
openssl ca -config $DIR_TMP/ssl.conf -name AlcasarCA -batch -days $SRVCERT_LIFETIME -in $SRVREQ -out $SRVCERT 2>> $DIR_TMP/openssl-log
rm -f $SRVREQ
cp -f $SRVCERT $SRVCHAIN  # in order to simplify the official intranet certificate import process
chmod a+r $CACERT $SRVCERT $SRVCHAIN

# Link certs in ALCASAR Control Center
if [ -s "$CACERT" -a -s "$CAKEY" -a -s "$SRVCERT" -a -s "$SRVKEY" ];
 then
 [ -d $DIR_WEB/certs ] || mkdir -p $DIR_WEB/certs
 rm -f $DIR_WEB/certs/*
 ln -s $CACERT $DIR_WEB/certs/certificat_alcasar_ca.crt
 ln -s $SRVCERT $DIR_WEB/certs/certificat_alcasar.crt
 rm -rf $DIR_TMP
 exit 0
else
 echo "Problème lors de la création des certificats (cf. $DIR_TMP/openssl-log)" >> $FIC_PARAM
 exit 1
fi
