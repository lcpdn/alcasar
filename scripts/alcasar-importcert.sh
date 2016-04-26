#!/bin/sh

# alcasar-importcert.sh
# by Raphaël, Hugo, Clément, Bettyna & rexy

# This script is distributed under the Gnu General Public License (GPL)

# Script permettant
# - d'importer des certificats sur Alcasar
# - de revenir au certificat par default

# This script allows
# - to import a certificate in Alcasar
# - to go back to the default certificate

SED="/bin/sed -ri"
DIR_CERT="/etc/pki/tls"
CONF_FILE="/usr/local/etc/alcasar.conf"
PRIVATE_IP_MASK=`grep PRIVATE_IP $CONF_FILE|cut -d"=" -f2`
PRIVATE_IP=`echo $PRIVATE_IP_MASK | cut -d"/" -f1`
DEFAULT_FQDN='alcasar.localdomain'

usage="Usage: alcasar-importcert.sh -i /path/to/certificate.crt -k /path/to/privatekey.key (-c /path/to/serverchain.crt) || alcasar-importcert.sh -d (Cette utilisation permet de revenir au certificat par default)"
nb_args=$#
arg1=$1


function defaultNdd()
{
	$SED "s/^HOSTNAME=.*/HOSTNAME=alcasar/g" /usr/local/etc/alcasar.conf
	$SED "s/^DOMAIN=.*/DOMAIN=localdomain/g" /usr/local/etc/alcasar.conf
	$SED "s/\.([a-zA-Z][a-zA-Z0-9-]+(\.[a-z]{2,4})?)/.localdomain/g" /etc/hosts
	$SED "s/alcasar\.([a-zA-Z0-9-]+(\.[a-z]{2,4})?)/alcasar.localdomain/g" /etc/chilli.conf
	$SED "s/^domain.*/domain\t\tlocaldomain/g" /etc/chilli.conf
	$SED "s/^ServerName.*/ServerName alcasar.localdomain/g" /etc/httpd/conf/httpd.conf
	$SED "s/^domain=.*/domain=localdomain/g" /etc/dnsmasq.conf /etc/dnsmasq-blackhole.conf /etc/dnsmasq-blacklist.conf /etc/dnsmasq-whitelist.conf
	hostnamectl set-hostname alcasar.localdomain
	$SED "s/^\tErrorDocument.*/\tErrorDocument 404 https:\/\/alcasar.localdomain\//g" /etc/httpd/conf/webapps.d/alcasar.conf
	$SED "s/^\tAuthDigestDomain.*/\tAuthDigestDomain alcasar.localdomain/g" /etc/httpd/conf/webapps.d/alcasar.conf
	$SED "s/^    ServerName.*/    ServerName alcasar.localdomain/g" /etc/httpd/conf/sites.d/00_default_vhosts.conf /etc/httpd/conf/sites.d/00_default_ssl_vhost.conf
}

function defaultCert()
{
	mv -f $DIR_CERT/certs/alcasar.crt.old $DIR_CERT/certs/alcasar.crt
	mv -f $DIR_CERT/private/alcasar.key.old $DIR_CERT/private/alcasar.key
	if [ -f $DIR_CERT/certs/server-chain.crt.old ]
	then
		mv $DIR_CERT/certs/server-chain.crt.old $DIR_CERT/certs/server-chain.crt
	#else 
	#	rm -f $DIR_CERT/certs/server-chain.crt
	fi
}

function domainName() # change the domain name in the conf files
{

	fqdn=$(openssl x509 -noout -subject -in $cert | sed -n '/^subject/s/^.*CN=//p' | cut -d'/' -f 1)
	hostname=`echo $fqdn | awk -F'.' '{ print $1 }'`
	domain=`echo $fqdn | awk -F'.' '{$1="";OFS=".";print $0}' |sed 's/^.//'`
	echo "fqdn=$fqdn hostname=$hostname domain=$domain"
	if [ "$fqdn" != "" ]
	then
		$SED "s/^HOSTNAME=.*/HOSTNAME=$hostname/g" /usr/local/etc/alcasar.conf
		$SED "s/^DOMAIN=.*/DOMAIN=$domain/g" /usr/local/etc/alcasar.conf
		cat <<EOF > /etc/hosts
127.0.0.1	localhost
$PRIVATE_IP	$fqdn $hostname
EOF
		$SED "s/^domain.*/domain\t\t$domain/g" /etc/chilli.conf
		$SED "s/^locationname.*/locationname\t$fqdn/g" /etc/chilli.conf
		$SED "s/^uamserver.*/uamserver\thttps:\/\/$fqdn\/intercept.php/g" /etc/chilli.conf
		$SED "s/^radiusnasid.*/radiusnasid\t$fqdn/g" /etc/chilli.conf
		$SED "s/^uamallowed.*/uamallowed\t$hostname,$fqdn/g" /etc/chilli.conf
		$SED "s/^ServerName.*/ServerName $fqdn/g" /etc/httpd/conf/httpd.conf
		$SED "s/^domain=.*/domain=$domain/g" /etc/dnsmasq.conf /etc/dnsmasq-blackhole.conf /etc/dnsmasq-blacklist.conf /etc/dnsmasq-whitelist.conf
		hostnamectl set-hostname $fqdn
		$SED "s/^\tErrorDocument.*/\tErrorDocument 404 https:\/\/$fqdn\//g" /etc/httpd/conf/webapps.d/alcasar.conf
		$SED "s/^\tAuthDigestDomain.*/\tAuthDigestDomain $fqdn/g" /etc/httpd/conf/webapps.d/alcasar.conf
		$SED "s/^    ServerName.*/    ServerName $fqdn/g" /etc/httpd/conf/sites.d/00_default_vhosts.conf /etc/httpd/conf/sites.d/00_default_ssl_vhost.conf /etc/httpd/conf/vhosts-ssl.default
	fi
}

function certImport()
{
	if [ ! -f "$DIR_CERT/certs/alcasar.crt.old" ]
	then
		echo "Backup of old cert (alcasar.crt)"
		mv $DIR_CERT/certs/alcasar.crt $DIR_CERT/certs/alcasar.crt.old
	fi
	if [ ! -f "$DIR_CERT/private/alcasar.key.old" ]
	then
		echo "Backup of old private key (alcasar.key)"
		mv $DIR_CERT/private/alcasar.key $DIR_CERT/private/alcasar.key.old
	fi
	cp $cert $DIR_CERT/certs/alcasar.crt
	cp $key $DIR_CERT/private/alcasar.key

	rm $cert $key

	chown root:apache $DIR_CERT/certs/alcasar.crt
	chown root:apache $DIR_CERT/private/alcasar.key

	chmod 750 $DIR_CERT/certs/alcasar.crt
	chmod 750 $DIR_CERT/private/alcasar.key
	if [ "$sc" != "" ]
	then
		echo "cert-chain exists"
		if [ ! -f "$DIR_CERT/certs/server-chain.crt.old" ]
		then
			echo "Backup of old cert-chain (server-chain.crt)"
			mv $DIR_CERT/certs/server-chain.crt $DIR_CERT/certs/server-chain.crt.old
		fi
		cp $sc $DIR_CERT/certs/server-chain.crt
		rm $sc
		chown root:apache $DIR_CERT/certs/server-chain.crt
		chmod 750 $DIR_CERT/certs/server-chain.crt
	fi
}


if [ $nb_args -eq 0 ]
then
	echo "$usage"
	exit 1
fi

case $arg1 in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	-i)
		arg3=$3
		arg5=$5
		cert=$2
		key=$4
		sc=$6

		if [ "$cert" == "" ] || [ "$key" == "" ]
		then
			echo "$usage"
			exit 1
		fi

		if [ ! -f "$cert" -o ! -f "$key" ]
		then
			echo "Certificate and/or private key not found"
			exit 1
		fi

		if [ ${cert: -4} != ".crt" ]
		then
			echo "Invalid certificate file"
			exit 1
		fi

		if [ ${key: -4} != ".key" ]
		then
			echo "Invalid private key"
			exit 1
		fi

		if [ "$arg5" != "-c" ] || [ ! -f "$sc" ]
		then
			echo "No server-chain given"
			echo "Importing certificate $cert with private key $key"
			sc=""
		else
			echo "Importing certificate $cert with private key $key and server-chain $sc"
		fi
		domainName $cert
		certImport $cert $key $sc
		for services in chilli dnsmasq dnsmasq-blackhole dnsmasq-blacklist dnsmasq-whitelist httpd
		do
			echo "restarting $services"; systemctl restart $services; sleep 1
		done
		;;
	-d)
		if [ -f "/etc/pki/tls/certs/alcasar.crt.old" -a -f "/etc/pki/tls/private/alcasar.key.old" ]
		then
			echo "Restoring default certificate"
			defaultCert
			defaultNdd
			for services in chilli dnsmasq dnsmasq-blackhole dnsmasq-blacklist dnsmasq-whitelist httpd
			do
				echo "restarting $services"; systemctl restart $services; sleep 1
			done
		fi
		;;
	*)
		echo "$usage"
		;;
esac
