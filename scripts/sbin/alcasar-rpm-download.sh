#!/bin/bash
# $Id: alcasar-rpm-download.sh 1767 2016-01-16 18:35:35Z richard $

# alcasar-urpmi.sh
# by Franck BOUIJOUX and Richard REY
# This script is distributed under the Gnu General Public License (GPL)

# récupération des RPM nécessaire dans un fichier tarball
# retrieve needed RPM in a tarball file

VERSION="4"
ARCH="i586" 
# ****** Alcasar needed RPMS - paquetages nécessaires au fonctionnement d'Alcasar ******
PACKAGES="vim-enhanced freeradius freeradius-mysql freeradius-ldap freeradius-web apache apache-mod_ssl apache-mod_php dansguardian postfix mariadb ntp bind-utils openssh-server php-xml php-ldap php-mysql php-mysqli php-mbstring php-sockets php-cli php-curl php-pdo_sqlite php-json rng-utils dnsmasq rsync clamav perl-rrdtool perl-MailTools perl-Socket6 fail2ban gnupg ulogd dkms-ipt_NETFLOW iptables-NETFLOW pm-fallback-policy ipset cronie-anacron gammu usbutils locales-en usb_modeswitch tinyproxy vnstat php-gd sudo iftop"

rpm_repository_sync ()
{
cat <<EOF > /etc/urpmi/urpmi.cfg
{
downloader: wget
}
EOF
urpmi.addmedia --probe-synthesis --mirrorlist ${!MIRRORLIST} core /media/core/release
urpmi.addmedia --update --probe-synthesis --mirrorlist ${!MIRRORLIST} core_updates /media/core/updates
}

rpm_error ()
{
echo
echo "Relancez l'installation ultérieurement."
echo "Si vous rencontrez à nouveau ce problème, modifier les variables MIRRORLIST[1&2] du fichier 'scripts/alcasar-urpmi.sh'"
echo "Try an other install later."
echo "If this problem occurs again, change the MIRRORLIST[1&2] variables in the file 'scripts/alcasar-urpmi.sh'"
}

# extract the current architecture (i586 ou X64)
fic=`cat /etc/product.id`
old="$IFS"
IFS=","
set $fic
for i in $*
do
	if [ "`echo $i|grep arch|cut -d'=' -f1`" == "arch" ]
	then 
		ARCH=`echo $i|cut -d"=" -f2`
	fi
done
IFS="$old"
# We prefer wget than curl
wget_exist=`rpm -qa|grep wget|wc -l`
if [ "$wget_exist" -eq "0" ]
then
	urpmi --no-verify-rpm --auto ../../conf/rpms/$ARCH/wget*.rpm
fi
# Set the RPM repository
MIRROR_NBR=2
#                       For french ALCASARistes
MIRRORLIST1="http://www.mirrorservice.org/sites/mageia.org/pub/mageia/distrib/$VERSION/$ARCH"
#                       For International install
MIRRORLIST2="http://mirrors.mageia.org/api/mageia.$VERSION.$ARCH.list"
try_nb="0"; nb_repository="0"
while [ "$nb_repository" != "2" ]
do
	try_nb=`expr $try_nb + 1`
	MIRRORLIST="MIRRORLIST$try_nb"
	rpm_repository_sync 
	nb_repository=`cat /etc/urpmi/urpmi.cfg|grep mirrorlist|wc -l`
	if [ "$nb_repository" != "2" ]
	then
		echo "Une erreur a été détectée lors de la synchronisation avec le dépot N°$try_nb."
		echo "An error occurs when synchronising the repositories N°$try_nb"
		if [ $(expr $try_nb) -eq $MIRROR_NBR ]
		then
			rpm_error
			exit 1
		fi
		echo "Voulez-vous tenter une synchronisation avec un autre dépôt?"
		echo "Do you wan't to try a synchronisation with an other repository?"
		response=0
		PTN='^[oOnNyY]$'
		until [[ $(expr $response : $PTN) -gt 0 ]]
		do
			read response
		done
		if [ "$response" = "n" ] || [ "$response" = "N" ] 
		then
			exit 1
		fi
	fi
done
# delete unused RPMs
echo "Cleaning the system : "
for rm_rpm in shorewall dhcp-server cyrus-sasl distcache-server avahi mandi radeontool mondo mindi
do
	/usr/sbin/urpme --auto $rm_rpm --auto-orphans 2>/dev/null
	echo -n "."
done
urpmi --clean
# download RPM in cache 
echo "Récupération des paquetages de mise à jour. Veuillez patienter ..."
echo "Updated RPM download. Please wait ..."
echo "Il est temps d'aller prendre un café :-) "
echo "You should now take a Beer ;-) "
urpmi --auto --auto-update --quiet --test --retry 2
if [ "$?" != "0" ]
then
	echo
	echo "Une erreur a été détectée lors de la récupération des paquetages."
	echo "An error occurs when downloading RPMS"
	rpm_error
	exit 1
fi
# update with cached RPM
urpmi --auto --auto-update --noclean
if [ "$?" != "0" ]
then
	echo
	echo "Une erreur a été détectée lors de la mise à jour des paquetages."
	echo "An error occurs when updating packages"
	rpm_error
	exit 1
fi

# Download of ALCASAR specifics RPM in cache (and test)
echo "Récupération des paquetages complémentaires. Veuillez patienter ..."
echo "Download of complementary packages. Please wait ..."
urpmi --auto $PACKAGES --quiet --test --retry 2
if [ "$?" != "0" ]
then
	echo
	echo "Une erreur a été détectée lors de la récupération des paquetages complémentaires."
	echo "An error occurs when downloading complementary packages"
	rpm_error
	exit 1
fi
echo "archive creation. Please wait..."
cd /var/cache/urpmi
tar -czf rpms-$ARCH.tar.gz rpms/
# Clean the RPM cache
urpmi --clean
mv rpms-$ARCH.tar.gz /root/
cd
echo "Your RPM archive file is /root/rpms-$ARCH.tar.gz"
exit 0

