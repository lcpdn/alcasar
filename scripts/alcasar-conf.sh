#/bin/bash
# $Id: alcasar-conf.sh 1777 2016-01-19 21:19:18Z richard $

# alcasar-conf.sh
# by REXY
# This script is distributed under the Gnu General Public License (GPL)

# Ce script permet la mise à jour ALCASAR 
#	- création de l'archive des fichiers de configuration dans "/tmp/alcasar-conf.tar.gz" (alcasar-conf.sh -create)
#	- chargement de l'archive de fichiers de configuration lors de la mise à jour d'un alcasar (alcasar-conf -load)
#	- application des directives du fichier de conf central "/usr/local/etc/alcasar.conf" lors d'un changement de conf réseau à chaud (alcasar-conf -apply) 
# This script allows ALCASAR update 
#	- create the configuration files backup "/tmp/alcasar-conf.tar.gz" (alcasar-conf.sh -create)
#	- load the bachup of configuration files during the update process (alcasar-conf -load)
#	- apply ALCASAR central configuration file "/usr/local/etc/alcasar.conf" when hot modification is needed (alcasar-conf -apply)

new="$(date +%G%m%d-%Hh%M)"  			# date et heure des fichiers
fichier="alcasar-conf-$new.tar.gz"		# nom du fichier de sauvegarde
DIR_UPDATE="/tmp/conf"				# répertoire de stockage des fichier de conf pour une mise à jour
DIR_WEB="/var/www/html"				# répertoire du centre de gestion
DIR_BIN="/usr/local/bin"			# répertoire des scripts d'admin
DIR_SBIN="/usr/local/sbin"			# répertoire des scripts d'admin
DIR_ETC="/usr/local/etc"			# répertoire des fichiers de conf
CONF_FILE="$DIR_ETC/alcasar.conf"		# main alcasar conf file
VERSION="/var/www/html/VERSION"			# contient la version en cours
EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`	# EXTernal InterFace
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`	# INTernal InterFace
HOSTNAME="alcasar"
DB_USER="radius"
radiuspwd=""
SED="/bin/sed -i"
RUNNING_VERSION=`cat $VERSION|cut -d" " -f1`
MAJ_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f1`
MIN_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f2|cut -c1`
UPD_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f3`
DOMAIN=`grep DOMAIN $CONF_FILE|cut -d"=" -f2` 2>/dev/null
DOMAIN=${DOMAIN:=localdomain}
DATE=`date '+%d %B %Y - %Hh%M'`
private_network_calc ()
{
	PRIVATE_PREFIX=`/bin/ipcalc -p $PRIVATE_IP $PRIVATE_NETMASK |cut -d"=" -f2`				# prefixe du réseau (ex. 24)
	PRIVATE_NETWORK=`/bin/ipcalc -n $PRIVATE_IP $PRIVATE_NETMASK| cut -d"=" -f2`				# @ réseau de consultation (ex.: 192.168.182.0)
	PRIVATE_NETWORK_MASK=$PRIVATE_NETWORK/$PRIVATE_PREFIX							# @ + masque du réseau de consult (192.168.182.0/24)
	classe=$((PRIVATE_PREFIX/8)); classe_sup=`expr $classe + 1`; classe_sup_sup=`expr $classe + 2`		# classes de réseau (ex.: 2=classe B, 3=classe C)
	PRIVATE_NETWORK_SHORT=`echo $PRIVATE_NETWORK | cut -d"." -f1-$classe`.					# @ compatible hosts.allow et hosts.deny (ex.: 192.168.182.)
	PRIVATE_BROADCAST=`/bin/ipcalc -b $PRIVATE_NETWORK_MASK | cut -d"=" -f2`				# private network broadcast (ie.: 192.168.182.255)
	private_network_ending=`echo $PRIVATE_NETWORK | cut -d"." -f$classe_sup`				# last octet of LAN address
	private_broadcast_ending=`echo $PRIVATE_BROADCAST | cut -d"." -f$classe_sup`				# last octet of LAN broadcast
	PRIVATE_FIRST_IP=`echo $PRIVATE_NETWORK | cut -d"." -f1-3`"."`expr $private_network_ending + 1`		# First network address (ex.: 192.168.182.1)
	PRIVATE_SECOND_IP=`echo $PRIVATE_NETWORK | cut -d"." -f1-3`"."`expr $private_network_ending + 2`	# second network address (ex.: 192.168.182.2)
	PRIVATE_LAST_IP=`echo $PRIVATE_BROADCAST | cut -d"." -f1-3`"."`expr $private_broadcast_ending - 1`	# last network address (ex.: 192.168.182.254)
	PRIVATE_MAC=`/sbin/ip link show $INTIF | grep ether | cut -d" " -f6| sed 's/:/-/g'| awk '{print toupper($0)}'`	# MAC address of INTIF
}

usage="Usage: alcasar-conf.sh {--create or -create} | {--load or -load} | {--apply or -apply}"
nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	nb_args=1
	args="-h"
fi
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	--create|-create)	
		[ -d $DIR_UPDATE ] && rm -rf $DIR_UPDATE
		mkdir $DIR_UPDATE
# backup the users database
		$DIR_SBIN/alcasar-mysql.sh -dump
		cp /var/Save/base/`ls -1t /var/Save/base|head -1` $DIR_UPDATE
# backup the logo
		cp -f $DIR_WEB/images/organisme.png $DIR_UPDATE
# backup Dansguardian files
		cp -f /etc/dansguardian/lists/exceptioniplist $DIR_UPDATE
		cp -f /etc/dansguardian/lists/urlregexplist $DIR_UPDATE
		cp -f /etc/dansguardian/lists/exceptionsitelist $DIR_UPDATE
		cp -f /etc/dansguardian/lists/bannedsitelist $DIR_UPDATE
		cp -f /etc/dansguardian/lists/exceptionurllist $DIR_UPDATE
		cp -f /etc/dansguardian/lists/bannedurllist $DIR_UPDATE
		cp -rf /etc/dansguardian/lists/blacklists/ossi $DIR_UPDATE
# backup of different conf files (main conf file, filtering, digest, etc)
		mkdir $DIR_UPDATE/etc/
		cp -rf $DIR_ETC/* $DIR_UPDATE/etc/
# backup of the security certificates (server & CA)
		cp -f /etc/pki/tls/certs/alcasar.crt* $DIR_UPDATE # autosigned and official if exist
		cp -f /etc/pki/tls/private/alcasar.key* $DIR_UPDATE # autosigned & official if exist
		cp -f /etc/pki/CA/alcasar-ca.crt $DIR_UPDATE
		cp -f /etc/pki/CA/private/alcasar-ca.key $DIR_UPDATE
		if [ -e /etc/pki/tls/certs/server-chain.crt ]; then
			cp -f /etc/pki/tls/certs/server-chain.crt $DIR_UPDATE
		else
			cp -f /etc/pki/tls/certs/alcasar.crt $DIR_UPDATE/server-chain.crt
		fi
# backup DNSMASQ conf file
	 	cp /etc/sysconfig/dnsmasq $DIR_UPDATE
# archive file creation
		cd /tmp
		tar -cf alcasar-conf.tar conf/
		gzip -f alcasar-conf.tar
		rm -rf $DIR_UPDATE
		;;
	--load|-load)
		cd /tmp
		tar -xf /tmp/alcasar-conf*.tar.gz
# Retrieve the logo
		[ -e $DIR_UPDATE/organisme.png ] && cp -f $DIR_UPDATE/organisme.png $DIR_WEB/images/
		chown apache:apache $DIR_WEB/images/organisme.png $DIR_WEB/intercept.php
# Retrieve the security certificates (CA and server)
		cp -f $DIR_UPDATE/alcasar-ca.crt* /etc/pki/CA/ # autosigned & official
		cp -f $DIR_UPDATE/alcasar-ca.key* /etc/pki/CA/private/ # autosigned & official
		cp -f $DIR_UPDATE/alcasar.crt /etc/pki/tls/certs/
		cp -f $DIR_UPDATE/alcasar.key /etc/pki/tls/private/
		[ -e $DIR_UPDATE/server-chain.crt ] &&	cp -f $DIR_UPDATE/server-chain.crt /etc/pki/tls/certs/
		chown -R root:apache /etc/pki
		chmod -R 750 /etc/pki
# Import of the users database
		gzip -dc < `ls $DIR_UPDATE/alcasar-users-database*` | mysql -u$DB_USER -p$radiuspwd
# Retrieve local parameters & 
	# !!! for this version (2.9.2) we need to create new digest accounts and Remove blacklist files (now in /usr/local/share)
	# !!! remove the first two lines for future versions
		[ -d $DIR_UPDATE/etc ] && rm -rf $DIR_UPDATE/etc/alcasar-dnsfilter*
		[ -d $DIR_UPDATE/etc ] && rm -rf $DIR_UPDATE/etc/digest/

		[ -d $DIR_UPDATE/etc ] && cp -rf $DIR_UPDATE/etc/* $DIR_ETC/
# Retrieve Dansguardian files
		cp -f $DIR_UPDATE/exceptioniplist /etc/dansguardian/lists/
		cp -f $DIR_UPDATE/exceptionsitelist /etc/dansguardian/lists/
		cp -f $DIR_UPDATE/urlregexplist /etc/dansguardian/lists/
		cp -f $DIR_UPDATE/bannedsitelist /etc/dansguardian/lists/ 
		cp -f $DIR_UPDATE/exceptionurllist /etc/dansguardian/lists/
		cp -f $DIR_UPDATE/bannedurllist /etc/dansguardian/lists/
		cp -rf $DIR_UPDATE/ossi /etc/dansguardian/lists/blacklists/
		chown -R dansguardian:apache /etc/dansguardian/lists
		chmod -R g+rw /etc/dansguardian/lists
# Adapt DNS/URL filtering
		PARENT_SCRIPT=`basename $0`
		export PARENT_SCRIPT
		$DIR_SBIN/alcasar-bl.sh -adapt
		$DIR_SBIN/alcasar-bl.sh -reload
# retrieve dnsmasq general config file
		[ -e $DIR_UPDATE/dnsmasq ] && cp -f $DIR_UPDATE/dnsmasq /etc/sysconfig/dnsmasq \
		&& chown root.root /etc/sysconfig/dnsmasq \
		&& chmod 644 /etc/sysconfig/dnsmasq
# admin profile update (admin + manager + backup)
		$DIR_SBIN/alcasar-profil.sh --list
# Start / Stop SSH Daemon
		ssh_active=`grep SSH= $CONF_FILE|cut -d"=" -f2`
		if [ $ssh_active = "on" ]
		then
			/usr/bin/systemctl -q enable sshd.service
		else
			/usr/bin/systemctl -q disable sshd.service
		fi
# modifications added with this version (2.9.2)
		# add "HOSTNAME=" in alcasar.conf
		hostname_defined=`grep ^HOSTNAME= $CONF_FILE|wc -l`
		if [ $hostname_defined = "0" ]
		then
			$SED "/^DOMAIN=/iHOSTNAME=alcasar" $CONF_FILE
		fi
# Remove the update folder
		rm -rf $DIR_UPDATE
		;;
	--apply|-apply)
		PTN="\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([012]?[0-9]|3[0-2])\b"
		PRIVATE_IP_MASK=`grep ^PRIVATE_IP $CONF_FILE|cut -d"=" -f2`
		check=$(echo $PRIVATE_IP_MASK | egrep $PTN)
		if [[ "$?" -ne 0 ]]
		then 
			echo "Syntax error for PRIVATE_IP_MASK ($PRIVATE_IP_MASK)"
			exit 0
		fi
		PUBLIC_IP_MASK=`grep ^PUBLIC_IP $CONF_FILE|cut -d"=" -f2`
		PTN="\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
		if [[ "$PUBLIC_IP_MASK" == "dhcp" ]]
		then
			PUBLIC_GATEWAY="dhcp"

		else
			check=$(echo $PUBLIC_IP_MASK | egrep $PTN)
			if [[ "$?" -ne 0 ]]
			then 
				echo "Syntax error for PUBLIC_IP_MASK ($PUBLIC_IP_MASK)"
				exit 0
			fi
			PUBLIC_IP=`echo $PUBLIC_IP_MASK | cut -d"/" -f1`
			PUBLIC_NETMASK=`/bin/ipcalc -m $PUBLIC_IP_MASK | cut -d"=" -f2`
			PUBLIC_GATEWAY=`grep ^GW $CONF_FILE|cut -d"=" -f2`
			check=$(echo $PUBLIC_GATEWAY | egrep $PTN)
			if [[ "$?" -ne 0 ]]
			then 
				echo "Syntax error for the Gateway IP ($PUBLIC_GATEWAY)"
				exit 0
			fi
		fi
		DNS1=`grep ^DNS1 $CONF_FILE|cut -d"=" -f2`
		check=$(echo $DNS1 | egrep $PTN)
		if [[ "$?" -ne 0 ]]
		then 
			echo "Syntax error for the IP address of the first DNS server ($DNS1)"
			exit 0
		fi
		DNS2=`grep ^DNS2 $CONF_FILE|cut -d"=" -f2`
		check=$(echo $DNS2 | egrep $PTN)
		if [[ "$?" -ne 0 ]]
		then 
			echo "Syntax error for the IP address of the second DNS server ($DNS2)"
			exit 0
		fi
		PRIVATE_IP=`echo $PRIVATE_IP_MASK | cut -d"/" -f1`
		PRIVATE_NETMASK=`/bin/ipcalc -m $PRIVATE_IP_MASK | cut -d"=" -f2`
		private_network_calc
		INSTALL_DATE=`grep INSTALL_DATE $CONF_FILE|cut -d"=" -f2`
		ORGANISME=`grep ORGANISM $CONF_FILE|cut -d"=" -f2`
 		DOMAIN=`grep DOMAIN $CONF_FILE|cut -d"=" -f2`
		DHCP_mode=`grep DHCP= $CONF_FILE|cut -d"=" -f2`
		if [ "$PARENT_SCRIPT" != "alcasar.sh" ] # don't launch on install stage
		then
			if [ $DHCP_mode = "off" ]
			then
				$DIR_SBIN/alcasar-dhcp.sh --off
			fi
# Implementation of the authentification LDAP
#			$DIR_SBIN/alcasar-ldap.sh --$INT_LDAP_active

# Logout everybody
			$DIR_SBIN/alcasar-logout.sh all		
# Services stop
			echo -n "Stop services : "
			for i in ntpd tinyproxy dnsmasq dnsmasq-whitelist dnsmasq-blacklist chilli network httpd
			do
				/usr/bin/systemctl stop $i && echo -n "$i, "
			done
			echo
		fi

# /etc/hosts
		$SED "/alcasar/s?.*?$PRIVATE_IP\talcasar alcasar.localdomain?g" /etc/hosts
# EXTIF config
		if [ $PUBLIC_IP_MASK == "dhcp" ]
		then
			cat <<EOF > /etc/sysconfig/network-scripts/ifcfg-$EXTIF
DEVICE=$EXTIF
BOOTPROTO=dhcp
DNS1=127.0.0.1
PEERDNS=no
RESOLV_MODS=yes
ONBOOT=yes
METRIC=10
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
MTU=$MTU
EOF
		else	
			cat <<EOF > /etc/sysconfig/network-scripts/ifcfg-$EXTIF
DEVICE=$EXTIF
BOOTPROTO=static
IPADDR=$PUBLIC_IP
NETMASK=$PUBLIC_NETMASK
GATEWAY=$PUBLIC_GATEWAY
DNS1=127.0.0.1
RESOLV_MODS=yes
ONBOOT=yes
METRIC=10
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
MTU=$MTU
EOF
		fi
# INTIF config (for bypass mode only)
		$SED "s?^IPADDR=.*?IPADDR=$PRIVATE_IP?" /etc/sysconfig/network-scripts/bypass-ifcfg-$INTIF
		$SED "s?^NETMASK=.*?NETMASK=$PRIVATE_NETMASK?" /etc/sysconfig/network-scripts/bypass-ifcfg-$INTIF
# NTP server
		$SED "/127.0.0.1/!s?^restrict.*?restrict $PRIVATE_NETWORK mask $PRIVATE_NETMASK nomodify notrap?g" /etc/ntp.conf
# host.allow 
		cat <<EOF > /etc/hosts.allow
ALL: LOCAL, 127.0.0.1, localhost, $PRIVATE_IP
sshd: ALL
ntpd: $PRIVATE_NETWORK_SHORT
EOF
# Alcasar Control Center
		$SED "s?^Listen.*?Listen $PRIVATE_IP:80?g" /etc/httpd/conf/httpd.conf
		FIC_MOD_SSL=`find /etc/httpd/conf/ -type f -name ssl.conf`
		$SED "s?^Listen.*?Listen $PRIVATE_IP:443?g" $FIC_MOD_SSL
		$SED "/127.0.0.1/!s?Allow from .*?Allow from $PRIVATE_NETWORK_MASK?g" /etc/httpd/conf/webapps.d/alcasar.conf
# Dialup_Admin
		$SED "s?^nas1_name:.*?nas1_name: alcasar-$ORGANISME?g" /etc/freeradius-web/naslist.conf
		$SED "s?^nas1_ip:.*?nas1_ip: $PRIVATE_IP?g" /etc/freeradius-web/naslist.conf
# coova
		$SED "s?^net.*?net\t\t$PRIVATE_NETWORK_MASK?g" /etc/chilli.conf
		$SED "s?^dns1.*?dns1\t\t$PRIVATE_IP?g" /etc/chilli.conf
		$SED "s?^dns2.*?dns2\t\t$PRIVATE_IP?g" /etc/chilli.conf
		$SED "s?^uamlisten.*?uamlisten\t$PRIVATE_IP?g" /etc/chilli.conf
		# modify the DHCP static ip file. Reserve the second IP address for INTIF (the first one is for tun0). Keep previous entries
		$SED "s?^$PRIVATE_MAC.*?$PRIVATE_MAC $PRIVATE_SECOND_IP?" $DIR_ETC/alcasar-ethers
# dnsmasq
		$SED "/127.0.0.1/!s?^listen-address=.*?listen-address=$PRIVATE_IP?g" /etc/dnsmasq.conf /etc/dnsmasq-blacklist.conf /etc/dnsmasq-whitelist.conf
		for i in /etc/dnsmasq.conf /etc/dnsmasq-blacklist.conf
		do
			$SED "/^server=/d" $i
			echo "server=$DNS1" >> $i
			echo "server=$DNS2" >> $i
		done
		$SED "s?^dhcp-range=.*?dhcp-range=$PRIVATE_SECOND_IP,$PRIVATE_LAST_IP,$PRIVATE_NETMASK,12h?g" /etc/dnsmasq.conf
		$SED "s?^dhcp-option=option:router.*?dhcp-option=option:router,$PRIVATE_IP?g" /etc/dnsmasq.conf
# tinyproxy			
		$SED "s?^Listen.*?Listen $PRIVATE_IP?g" /etc/tinyproxy/tinyproxy.conf
# DG + BL
		$SED "s?^filterip.*?filterip = $PRIVATE_IP?g" /etc/dansguardian/dansguardian.conf
# Watchdog
		$SED "s?^PRIVATE_IP=.*?PRIVATE_IP=\"$PRIVATE_IP\"?g" $DIR_BIN/alcasar-watchdog.sh
# Prompts
		$SED "s?^ORGANISME.*?ORGANISME=$ORGANISME?g" /etc/bashrc
# sudoers
		$SED "s?^Host_Alias.*?Host_Alias	LAN_ORG=$PRIVATE_NETWORK/$PRIVATE_NETMASK,localhost		#réseau de l'organisme?g" /etc/sudoers
		if [ "$PARENT_SCRIPT" != "alcasar.sh" ] # don't launch on install stage
		then
# Services start
			/usr/bin/systemctl start network && echo -n "Start service : network" && sleep 1
			$DIR_SBIN/alcasar-dhcp.sh -$DHCP_mode && echo -n ", coova" # apply DHCP mode and start coova
			for i in dnsmasq tinyproxy ntpd httpd
				do
					sleep 1
					/usr/bin/systemctl start $i && echo -n ", $i"
				done
			$DIR_SBIN/alcasar-bl.sh -reload && echo ", dnsmasq-blacklist, dnsmasq-whitelist, iptables"
		fi
# Start / Stop SSH Daemon
		ssh_active=`grep SSH= $CONF_FILE|cut -d"=" -f2`
		if [ $ssh_active = "on" ]
		then
			/usr/bin/systemctl enable sshd.service
			if [ "$PARENT_SCRIPT" != "alcasar.sh" ] # don't launch on install stage
			then
				/usr/bin/systemctl start sshd.service
			fi
		else
			/usr/bin/systemctl disable sshd.service
			if [ "$PARENT_SCRIPT" != "alcasar.sh" ] # don't launch on install stage
			then
				/usr/bin/systemctl stop sshd.service
			fi
		fi
		;;
	*)
		echo "Argument inconnu :$1";
		echo "$usage"
		exit 1
		;;
esac

