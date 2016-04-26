#!/bin/bash
#  $Id: alcasar.sh 1782 2016-01-21 17:24:12Z franck $ 

# alcasar.sh

# ALCASAR Install script -  CopyLeft ALCASAR Team [Rexy + 3abtux + Steweb + Crox + ...] 
# Ce programme est un logiciel libre ; This software is free and open source
# elle que publiée par la Free Software Foundation ; soit la version 3 de la Licence. 
# Ce programme est distribué dans l'espoir qu'il sera utile, mais SANS AUCUNE GARANTIE ; 
# sans même une garantie implicite de COMMERCIABILITE ou DE CONFORMITE A UNE UTILISATION PARTICULIERE. 
# Voir la Licence Publique Générale GNU pour plus de détails. 

#  team@alcasar.net

# by Franck BOUIJOUX, Pascal LEVANT and Richard REY
# This script is distributed under the Gnu General Public License (GPL)

# Script d'installation d'ALCASAR (Application Libre pour le Contrôle d'Accès Sécurisé et Authentifié au Réseau)
# ALCASAR est architecturé autour d'une distribution Linux Mageia minimaliste et les logiciels libres suivants :
# Install script for ALCASAR (a secured and authenticated Internet access control captive portal)
# ALCASAR is based on a stripped Mageia (LSB) with the following open source softwares : 
# Coovachilli, freeradius, mariaDB, apache, netfilter, dansguardian, ntpd, openssl, dnsmasq, gammu, havp, libclamav, Ulog, fail2ban, tinyproxy, NFsen and NFdump

# Options :
#       -i or --install
#       -u or --uninstall

# Functions :
#	testing			: connectivity tests, free space test and mageia version test
#	init			: Installation of RPM and scripts
#	network			: Network parameters
#	ACC			: ALCASAR Control Center installation
#	CA			: Certification Authority initialization
#	init_db			: Initilization of radius database managed with MariaDB
#	radius			: FreeRadius initialisation
#	radius_web		: copy ans modifiy original "freeradius web" in ACC
#	chilli			: coovachilli initialisation (+authentication page)
#	dansguardian		: DansGuardian filtering HTTP proxy configuration
#	antivirus		: HAVP + libclamav configuration
#	tinyproxy		: little proxy for user filtered with "WL + antivirus" and "antivirus"
#	ulogd			: log system in userland (match NFLOG target of iptables)
#	nfsen		:	: Configuration du grapheur nfsen pour apache 
#	dnsmasq			: Name server configuration
#	vnstat			: little network stat daemon
#	BL			: BlackList of Toulouse configuration : split into 3 BL (for Dnsmasq, for dansguardian and for Netfilter)
#	cron			: Logs export + watchdog + connexion statistics
#	fail2ban		: Fail2ban IDS installation and configuration
#	gammu_smsd		: Autoregister addon via SMS (gammu-smsd)
#	post_install		: Security, log rotation, etc.

DATE=`date '+%d %B %Y - %Hh%M'`
DATE_SHORT=`date '+%d/%m/%Y'`
Lang=`echo $LANG|cut -c 1-2`
mode="install"
# ******* Files parameters - paramètres fichiers *********
DIR_INSTALL=`pwd`				# current directory 
DIR_CONF="$DIR_INSTALL/conf"			# install directory (with conf files)
DIR_SCRIPTS="$DIR_INSTALL/scripts"		# install directory (with script files)
DIR_SAVE="/var/Save"				# backup directory (traceability_log, user_db, security_log)
DIR_WEB="/var/www/html"				# directory of APACHE
DIR_DG="/etc/dansguardian"			# directory of DansGuardian
DIR_ACC="$DIR_WEB/acc"				# directory of the 'ALCASAR Control Center'
DIR_DEST_BIN="/usr/local/bin"			# directory of ALCASAR scripts
DIR_DEST_SBIN="/usr/local/sbin"			# directory of ALCASAR admin scripts
DIR_DEST_ETC="/usr/local/etc"			# directory of ALCASAR conf files
DIR_DEST_SHARE="/usr/local/share"		# directory of share files used by ALCASAR (dnsmasq for instance)
CONF_FILE="$DIR_DEST_ETC/alcasar.conf"		# central ALCASAR conf file
PASSWD_FILE="/root/ALCASAR-passwords.txt"	# text file with the passwords and shared secrets
# ******* DBMS parameters - paramètres SGBD ********
DB_RADIUS="radius"				# database name used by FreeRadius server
DB_USER="radius"				# user name allows to request the users database
DB_GAMMU="gammu"				# database name used by Gammu-smsd
# ******* Network parameters - paramètres réseau *******
HOSTNAME="alcasar"				# default hostname
DOMAIN="localdomain"				# default local domain
EXTIF=`/sbin/ip route|grep default|head -n1|cut -d" " -f5`						# EXTIF is connected to the ISP broadband modem/router (In France : Box-FAI)
INTIF=`/sbin/ip	link|grep '^[[:digit:]]:'|grep -v "lo\|$EXTIF\|tun0"|head -n1|cut -d" " -f2|tr -d ":"`	# INTIF is connected to the consultation network
MTU="1500"
DEFAULT_PRIVATE_IP_MASK="192.168.182.1/24"	# Default ALCASAR IP address
# ****** Paths - chemin des commandes *******
SED="/bin/sed -i"
# ****************** End of global parameters *********************

license ()
{
	if [ $Lang == "fr" ]
	then
		cat $DIR_INSTALL/gpl-warning.fr.txt | more
	else
		cat $DIR_INSTALL/gpl-warning.txt | more
	fi
	response=0
	PTN='^[oOyYnN]$'
	until [[ $(expr $response : $PTN) -gt 0 ]]
	do
		if [ $Lang == "fr" ]
			then echo -n "Acceptez-vous les termes de cette licence (O/n)? : "
			else echo -n "Do you accept the terms of this license (Y/n)? : "
		fi
		read response
	done
	if [ "$response" = "n" ] || [ "$response" = "N" ]
	then
		exit 1
	fi
}

header_install ()
{
	clear
	echo "-----------------------------------------------------------------------------"
	echo "                     ALCASAR V$VERSION Installation"
	echo "Application Libre pour le Contrôle d'Accès Sécurisé et Authentifié au Réseau"
	echo "-----------------------------------------------------------------------------"
}

##################################################################
##			Function "testing"			##
## - Test of Mageia version					##
## - Test of ALCASAR version (if already installed)		##
## - Test of free space on /var  (>10G)				##
## - Test of Internet access					##
##################################################################
testing ()
{
# Test of Mageia version
# extract the current Mageia version and hardware architecture (i586 ou X64)
	fic=`cat /etc/product.id`
	unknown_os=0
	old="$IFS"
	IFS=","
	set $fic
	for i in $*
	do
		if [ "`echo $i|grep distribution|cut -d'=' -f1`" == "distribution" ]
			then 
			DISTRIBUTION=`echo $i|cut -d"=" -f2`
			unknown_os=`expr $unknown_os + 1`
		fi
		if [ "`echo $i|grep version|cut -d'=' -f1`" == "version" ]
			then 
			CURRENT_VERSION=`echo $i|cut -d"=" -f2`
			unknown_os=`expr $unknown_os + 1`
		fi
		if [ "`echo $i|grep arch|cut -d'=' -f1`" == "arch" ]
			then 
			ARCH=`echo $i|cut -d"=" -f2`
			unknown_os=`expr $unknown_os + 1`
		fi
	done
	IFS="$old"
# Test if ALCASAR is already installed
	if [ -e $CONF_FILE ]
	then
		current_version=`cat $CONF_FILE | grep VERSION | cut -d"=" -f2`
		if [ $Lang == "fr" ]
			then echo -n "La version "; echo -n $current_version ; echo " d'ALCASAR est déjà installée";
			else echo -n "ALCASAR Version "; echo -n $current_version ; echo " is already installed";
		fi
		response=0
		PTN='^[oOnNyY]$'
		until [[ $(expr $response : $PTN) -gt 0 ]]
		do
			if [ $Lang == "fr" ]
				then echo -n "Voulez-vous effectuer une mise à jour (O/n)? ";
				else echo -n "Do you want to update (Y/n)?";
			 fi
			read response
		done
		if [ "$response" = "n" ] || [ "$response" = "N" ] 
		then
			rm -f /tmp/alcasar-conf*
		else
# Retrieve former NICname
			EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`				# EXTernal InterFace
			INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`				# INTernal InterFace
# Create the current conf file
			$DIR_SCRIPTS/alcasar-conf.sh --create
			mode="update"
		fi
	fi
	if [[ ( $unknown_os != 3 ) || ("$DISTRIBUTION" != "Mageia" ) || ( "$CURRENT_VERSION" != "4" ) ]]
		then
		if [ -e /tmp/alcasar-conf.tar.gz ] # update
			then
			echo
			if [ $Lang == "fr" ]
				then	
				echo "La mise à jour automatique d'ALCASAR ne peut pas être réalisée."
				echo "1 - Récupérez le fichier de configuration actuel (/tmp/alcasar-conf.tar.gz)."
				echo "2 - Installez Linux-Mageia 4.1 (cf. doc d'installation)"
				echo "3 - recopiez le fichier 'alcasar-conf.tar.gz' dans le répertoire '/tmp' avant de lancer l'installation d'ALCASAR"
			else
				echo "The automatic update of ALCASAR can't be performed."
				echo "1 - Retrieve the configuration file (/tmp/alcasar-conf.tar.gz)"
				echo "2 - Install Linux-Mageia 4.1 (cf. installation doc)"
				echo "3 - Copy again the file 'alcasar-conf.tar.gz' in the folder '/tmp' before launching the installation of ALCASAR"
			fi
		else
			if [ $Lang == "fr" ]
				then	
				echo "L'installation d'ALCASAR ne peut pas être réalisée."
			else
				echo "The installation of ALCASAR can't be performed."
			fi
		fi
		echo
		if [ $Lang == "fr" ]
			then	
			echo "Le système d'exploitation doit être remplacé (Mageia4.1)"
		else
			echo "The OS must be replaced (Mageia4.1)"
		fi
		exit 0
	fi
	if [ ! -d /var/log/netflow/porttracker ]
		then
# Test of free space on /var
		free_space=`df -BG --output=avail /var|tail -1|tr -d [:space:]G`
		if [ $free_space -lt 10 ]
			then
			if [ $Lang == "fr" ]
				then echo "place disponible sur /var insufisante ($free_space Go au lieu de 10 Go au minimum)"
				else echo "not enough free space on /var ($free_space GB instead of at least 10 GB)"
			fi
		exit 0
		fi
	fi
	if [ $Lang == "fr" ]
		then echo -n "Tests des paramètres réseau : "
		else echo -n "Network parameters tests : "
	fi
# Test of Ethernet links state
	DOWN_IF=`/sbin/ip link|grep "NO-CARRIER"|cut -d":" -f2|tr -d " "`
	for i in $DOWN_IF
	do
		if [ $Lang == "fr" ]
		then 
			echo "Échec"
			echo "Le lien réseau de la carte $i n'est pas actif."
			echo "Assurez-vous que cette carte est bien connectée à un équipement (commutateur, A.P., etc.)"
		else
			echo "Failed"
			echo "The link state of $i interface is down."
			echo "Make sure that this network card is connected to a switch or an A.P."
		fi
		exit 0
	done
	echo -n "."

# Test EXTIF config files
	PUBLIC_IP_MASK=`ip addr show $EXTIF|grep "inet "|cut -d" " -f6`
	PUBLIC_IP=`echo $PUBLIC_IP_MASK | cut -d"/" -f1`
	PUBLIC_GATEWAY=`ip route list|grep $EXTIF|grep ^default|cut -d" " -f3`
	if [ `echo $PUBLIC_IP|wc -c` -lt 7 ] || [ `echo $PUBLIC_GATEWAY|wc -c` -lt 7 ]
	then
		if [ $Lang == "fr" ]
		then 
			echo "Échec"
			echo "La carte réseau connectée à Internet ($EXTIF) n'est pas correctement configurée."
			echo "Renseignez les champs suivants dans le fichier '/etc/sysconfig/network-scripts/ifcfg-$EXTIF' :"
			echo "Appliquez les changements : 'systemctl restart network'"
		else
			echo "Failed"
			echo "The Internet connected network card ($EXTIF) isn't well configured."
			echo "The folowing parametres must be set in the file '/etc/sysconfig/network-scripts/ifcfg-$EXTIF' :"
			echo "Apply the new configuration 'systemctl restart network'"
		fi
		echo "DEVICE=$EXTIF"
		echo "IPADDR="
		echo "NETMASK="
		echo "GATEWAY="
		echo "DNS1="
		echo "DNS2="
		echo "ONBOOT=yes"
		exit 0
	fi
	echo -n "."

# Test if router is alive (Box FAI)
	if [ `ip route list|grep $EXTIF|grep -c ^default` -ne "1" ] ; then
		if [ $Lang == "fr" ]
		then 
			echo "Échec"
			echo "Vous n'avez pas configuré l'accès à Internet ou le câble réseau n'est pas sur la bonne carte."
			echo "Réglez ce problème puis relancez ce script."
		else
			echo "Failed"
			echo "You haven't configured Internet access or Internet link is on the wrong Ethernet card"
			echo "Resolv this problem, then restart this script."
		fi
		exit 0
	fi
	echo -n "."
# On teste le lien vers le routeur par defaut
	arp_reply=`/usr/sbin/arping -b -I$EXTIF -c1 -w2 $PUBLIC_GATEWAY|grep response|cut -d" " -f2`
	if [ $(expr $arp_reply) -eq 0 ]
	       	then
		if [ $Lang == "fr" ]
		then 
			echo "Échec"
			echo "Le routeur de site ou la Box Internet ($PUBLIC_GATEWAY) ne répond pas."
			echo "Réglez ce problème puis relancez ce script."
		else
			echo "Failed"
			echo "The Internet gateway doesn't answered"
			echo "Resolv this problem, then restart this script."
		fi
		exit 0
	fi
	echo -n "."
# On teste la connectivité Internet
	rm -rf /tmp/con_ok.html
	/usr/bin/curl www.google.fr -s -o /tmp/con_ok.html
	if [ ! -e /tmp/con_ok.html ]
	then
		if [ $Lang == "fr" ]
		then 
			echo "La tentative de connexion vers Internet a échoué (google.fr)."
			echo "Vérifiez que la carte $EXTIF est bien connectée au routeur du FAI."
			echo "Vérifiez la validité des adresses IP des DNS."
		else
			echo "The Internet connection try failed (google.fr)."
			echo "Please, verify that the $EXTIF card is connected with the Internet gateway."
			echo "Verify the DNS IP addresses"
		fi
		exit 0
	fi
	rm -rf /tmp/con_ok.html
	echo ". : ok"
} # end of testing ()

##################################################################
##			Function "init"				##
## - Création du fichier "/root/ALCASAR_parametres.txt"		##
## - Installation et modification des scripts du portail	##
##################################################################
init ()
{
	if [ "$mode" != "update" ]
	then
# On affecte le nom d'organisme
		header_install
		ORGANISME=!
		PTN='^[a-zA-Z0-9-]*$'
		until [[ $(expr $ORGANISME : $PTN) -gt 0 ]]
                do
			if [ $Lang == "fr" ]
			       	then echo -n "Entrez le nom de votre organisme : "
				else echo -n "Enter the name of your organism : "
			fi
			read ORGANISME
			if [ "$ORGANISME" == "" ]
				then
				ORGANISME=!
			fi
		done
	fi
# On crée aléatoirement les mots de passe et les secrets partagés
	rm -f $PASSWD_FILE
	grubpwd=`cat /dev/urandom | tr -dc [:alnum:] | head -c8`
	echo -n "Password to protect the GRUB boot menu (!!!qwerty keyboard) : " > $PASSWD_FILE
	echo "$grubpwd" >> $PASSWD_FILE
	md5_grubpwd=`/usr/bin/openssl passwd -1 $grubpwd`
	$SED "/^password.*/d" /boot/grub/menu.lst
	$SED "1ipassword --md5 $md5_grubpwd" /boot/grub/menu.lst
	mysqlpwd=`cat /dev/urandom | tr -dc [:alnum:] | head -c8`
	echo -n "Name and password of Mysql/mariadb administrator : " >> $PASSWD_FILE
	echo "root / $mysqlpwd" >> $PASSWD_FILE
	radiuspwd=`cat /dev/urandom | tr -dc [:alnum:] | head -c8`
	echo -n "Name and password of Mysql/mariadb user : " >> $PASSWD_FILE
	echo "$DB_USER / $radiuspwd" >> $PASSWD_FILE
	secretuam=`cat /dev/urandom | tr -dc [:alnum:] | head -c8`
	echo -n "Shared secret between the script 'intercept.php' and coova-chilli : " >> $PASSWD_FILE
	echo "$secretuam" >> $PASSWD_FILE
	secretradius=`cat /dev/urandom | tr -dc [:alnum:] | head -c8`
	echo -n "Shared secret between coova-chilli and FreeRadius : " >> $PASSWD_FILE
	echo "$secretradius" >> $PASSWD_FILE
	chmod 640 $PASSWD_FILE
# Scripts and conf files copy 
#  - in /usr/local/bin :  alcasar-{CA.sh,conf.sh,import-clean.sh,iptables-bypass.sh,iptables.sh,log.sh,watchdog.sh}
	cp -f $DIR_SCRIPTS/alcasar* $DIR_DEST_BIN/. ; chown root:root $DIR_DEST_BIN/alcasar* ; chmod 740 $DIR_DEST_BIN/alcasar*
#  - in /usr/local/sbin :  alcasar-{bl.sh,bypass.sh,dateLog.sh,havp.sh,logout.sh,mysql.sh,nf.sh,profil.sh,uninstall.sh,version-list.sh,load-balancing.sh}
	cp -f $DIR_SCRIPTS/sbin/alcasar* $DIR_DEST_SBIN/. ; chown root:root $DIR_DEST_SBIN/alcasar* ; chmod 740 $DIR_DEST_SBIN/alcasar*
#  - in /usr/local/etc : alcasar-{bl-categories-enabled,dns-name,iptables-local.sh,services}
	cp -f $DIR_CONF/etc/alcasar* $DIR_DEST_ETC/. ; chown root:apache $DIR_DEST_ETC/alcasar* ; chmod 660 $DIR_DEST_ETC/alcasar*
	$SED "s?^radiussecret.*?radiussecret=\"$secretradius\"?g" $DIR_DEST_SBIN/alcasar-logout.sh
	$SED "s?^DB_RADIUS=.*?DB_RADIUS=\"$DB_RADIUS\"?g" $DIR_DEST_SBIN/alcasar-mysql.sh
	$SED "s?^DB_USER=.*?DB_USER=\"$DB_USER\"?g" $DIR_DEST_SBIN/alcasar-mysql.sh $DIR_DEST_BIN/alcasar-conf.sh
	$SED "s?^radiuspwd=.*?radiuspwd=\"$radiuspwd\"?g" $DIR_DEST_SBIN/alcasar-mysql.sh $DIR_DEST_BIN/alcasar-conf.sh
# generate central conf file
	cat <<EOF > $CONF_FILE
##########################################
##                                      ##
##          ALCASAR Parameters          ##
##                                      ##
##########################################

INSTALL_DATE=$DATE
VERSION=$VERSION
ORGANISM=$ORGANISME
HOSTNAME=$HOSTNAME
DOMAIN=$DOMAIN
EOF
	chmod o-rwx $CONF_FILE
} # End of init ()

##################################################################
##			Function "network"			##
## - Définition du plan d'adressage du réseau de consultation	##
## - Nommage DNS du système 					##
## - Configuration de l'interface INTIF (réseau de consultation)##
## - Modification du fichier /etc/hosts				##
## - Configuration du serveur de temps (NTP)			##
## - Renseignement des fichiers hosts.allow et hosts.deny	##
##################################################################
network ()
{
	header_install
	if [ "$mode" != "update" ]
		then
		if [ $Lang == "fr" ]
			then echo "Par défaut, l'adresse IP d'ALCASAR sur le réseau de consultation est : $DEFAULT_PRIVATE_IP_MASK"
			else echo "The default ALCASAR IP address on consultation network is : $DEFAULT_PRIVATE_IP_MASK"
		fi
		response=0
		PTN='^[oOyYnN]$'
		until [[ $(expr $response : $PTN) -gt 0 ]]
		do
			if [ $Lang == "fr" ]
				then echo -n "Voulez-vous utiliser cette adresse et ce plan d'adressage (recommandé) (O/n)? : "
				else echo -n "Do you want to use this IP address and this IP addressing plan (recommanded) (Y/n)? : "
			fi
			read response
		done
		if [ "$response" = "n" ] || [ "$response" = "N" ]
		then
			PRIVATE_IP_MASK="0"
			PTN='^\([01]\?[[:digit:]][[:digit:]]\?\|2[0-4][[:digit:]]\|25[0-5]\).\([01]\?[[:digit:]][[:digit:]]\?\|2[0-4][[:digit:]]\|25[0-5]\).\([01]\?[[:digit:]][[:digit:]]\?\|2[0-4][[:digit:]]\|25[0-5]\).\([01]\?[[:digit:]][[:digit:]]\?\|2[0-4][[:digit:]]\|25[0-5]\)/[012]\?[[:digit:]]$'
			until [[ $(expr $PRIVATE_IP_MASK : $PTN) -gt 0 ]]
			do
				if [ $Lang == "fr" ]
					then echo -n "Entrez l'adresse IP d'ALCASAR au format CIDR (a.b.c.d/xx) : "
					else echo -n "Enter ALCASAR IP address in CIDR format (a.b.c.d/xx) : "
				fi
				read PRIVATE_IP_MASK
			done
		else
       			PRIVATE_IP_MASK=$DEFAULT_PRIVATE_IP_MASK
		fi
	else
		PRIVATE_IP_MASK=`grep PRIVATE_IP conf/etc/alcasar.conf|cut -d"=" -f2` 
		rm -rf conf/etc/alcasar.conf
	fi
# Define LAN side global parameters
	hostnamectl set-hostname $HOSTNAME.$DOMAIN
	PRIVATE_NETWORK=`/bin/ipcalc -n $PRIVATE_IP_MASK | cut -d"=" -f2`				# private network address (ie.: 192.168.182.0)
	private_network_ending=`echo $PRIVATE_NETWORK | cut -d"." -f4`					# last octet of LAN address
	PRIVATE_NETMASK=`/bin/ipcalc -m $PRIVATE_IP_MASK | cut -d"=" -f2`				# private network mask (ie.: 255.255.255.0)
	PRIVATE_PREFIX=`/bin/ipcalc -p $PRIVATE_IP_MASK |cut -d"=" -f2`					# network prefix (ie. 24)
	PRIVATE_IP=`echo $PRIVATE_IP_MASK | cut -d"/" -f1`						# ALCASAR private ip address (consultation LAN side)
	if [ $PRIVATE_IP == $PRIVATE_NETWORK ]								# when entering network address instead of ip address
		then
		PRIVATE_IP=`echo $PRIVATE_NETWORK | cut -d"." -f1-3`"."`expr $private_network_ending + 1`	
		PRIVATE_IP_MASK=`echo $PRIVATE_IP/$PRIVATE_PREFIX`
	fi	
	private_ip_ending=`echo $PRIVATE_IP | cut -d"." -f4`						# last octet of LAN address
	PRIVATE_SECOND_IP=`echo $PRIVATE_IP | cut -d"." -f1-3`"."`expr $private_ip_ending + 1`		# second network address (ex.: 192.168.182.2)
	PRIVATE_NETWORK_MASK=$PRIVATE_NETWORK/$PRIVATE_PREFIX						# ie.: 192.168.182.0/24
	classe=$((PRIVATE_PREFIX/8))									# ie.: 2=classe B, 3=classe C
	PRIVATE_NETWORK_SHORT=`echo $PRIVATE_NETWORK | cut -d"." -f1-$classe`.				# compatibility with hosts.allow et hosts.deny (ie.: 192.168.182.)
	PRIVATE_BROADCAST=`/bin/ipcalc -b $PRIVATE_NETWORK_MASK | cut -d"=" -f2`			# private network broadcast (ie.: 192.168.182.255)
	private_broadcast_ending=`echo $PRIVATE_BROADCAST | cut -d"." -f4`				# last octet of LAN broadcast
	PRIVATE_FIRST_IP=`echo $PRIVATE_NETWORK | cut -d"." -f1-3`"."`expr $private_network_ending + 1`	# First network address (ex.: 192.168.182.1)
	PRIVATE_LAST_IP=`echo $PRIVATE_BROADCAST | cut -d"." -f1-3`"."`expr $private_broadcast_ending - 1`	# last network address (ex.: 192.168.182.254)
	PRIVATE_MAC=`/sbin/ip link show $INTIF | grep ether | cut -d" " -f6| sed 's/:/-/g'| awk '{print toupper($0)}'` 	# MAC address of INTIF
# Define Internet parameters
	DNS1=`grep ^nameserver /etc/resolv.conf|awk -F" " '{print $2}'|head -n 1`				# 1st DNS server
	nb_dns=`grep ^nameserver /etc/resolv.conf|wc -l`
	if [ $nb_dns == 2 ]
		then
		DNS2=`grep ^nameserver /etc/resolv.conf|cut -d" " -f2|tail -n 1`			# 2nd DNS server (if exist)
	fi
	DNS1=${DNS1:=208.67.220.220}
	DNS2=${DNS2:=208.67.222.222}
	PUBLIC_NETMASK=`/bin/ipcalc -m $PUBLIC_IP_MASK | cut -d"=" -f2`
	PUBLIC_PREFIX=`/bin/ipcalc -p $PUBLIC_IP $PUBLIC_NETMASK|cut -d"=" -f2`
	PUBLIC_NETWORK=`/bin/ipcalc -n $PUBLIC_IP/$PUBLIC_PREFIX|cut -d"=" -f2`
# Wrtie the conf file
	echo "EXTIF=$EXTIF" >> $CONF_FILE
	echo "INTIF=$INTIF" >> $CONF_FILE
	IP_SETTING=`grep BOOTPROTO /etc/sysconfig/network-scripts/ifcfg-$EXTIF|cut -d"=" -f2`		# IP setting (static or dynamic)
	if [ $IP_SETTING == "dhcp" ]
		then
		echo "PUBLIC_IP=dhcp" >> $CONF_FILE
		echo "GW=dhcp" >> $CONF_FILE
	else
		echo "PUBLIC_IP=$PUBLIC_IP/$PUBLIC_PREFIX" >> $CONF_FILE
		echo "GW=$PUBLIC_GATEWAY" >> $CONF_FILE
	fi
	echo "DNS1=$DNS1" >> $CONF_FILE
	echo "DNS2=$DNS2" >> $CONF_FILE
	echo "PUBLIC_MTU=$MTU" >> $CONF_FILE
	echo "PRIVATE_IP=$PRIVATE_IP_MASK" >> $CONF_FILE
	echo "DHCP=on" >> $CONF_FILE
	echo "EXT_DHCP_IP=none" >> $CONF_FILE
	echo "RELAY_DHCP_IP=none" >> $CONF_FILE
	echo "RELAY_DHCP_PORT=none" >> $CONF_FILE
	echo "PROTOCOLS_FILTERING=off" >> $CONF_FILE
	echo "INT_DNS_DOMAIN=none" >> $CONF_FILE
	echo "INT_DNS_IP=none" >> $CONF_FILE
	echo "INT_DNS_ACTIVE=off" >> $CONF_FILE
# network default
	[ -e /etc/sysconfig/network.default ] || cp /etc/sysconfig/network /etc/sysconfig/network.default
	cat <<EOF > /etc/sysconfig/network
NETWORKING=yes
FORWARD_IPV4=true
EOF
# /etc/hosts config
	[ -e /etc/hosts.default ] || cp /etc/hosts /etc/hosts.default
	cat <<EOF > /etc/hosts
127.0.0.1	localhost
$PRIVATE_IP	$HOSTNAME.$DOMAIN $HOSTNAME
EOF
# EXTIF (Internet) config
	[ -e /etc/sysconfig/network-scripts/default-ifcfg-$EXTIF ] || cp /etc/sysconfig/network-scripts/ifcfg-$EXTIF /etc/sysconfig/network-scripts/default-ifcfg-$EXTIF
	if [ $IP_SETTING == "dhcp" ]
		then
		cat <<EOF > /etc/sysconfig/network-scripts/ifcfg-$EXTIF
DEVICE=$EXTIF
BOOTPROTO=dhcp
DNS1=127.0.0.1
PEERDNS=no
RESOLV_MODS=yes
ONBOOT=yes
NOZEROCONF=yes
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
NOZEROCONF=yes
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
MTU=$MTU
EOF
	fi
# Config INTIF (consultation LAN) in normal mode
	cat <<EOF > /etc/sysconfig/network-scripts/ifcfg-$INTIF
DEVICE=$INTIF
BOOTPROTO=static
ONBOOT=yes
NOZEROCONF=yes
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
EOF
	cp -f /etc/sysconfig/network-scripts/ifcfg-$INTIF /etc/sysconfig/network-scripts/default-ifcfg-$INTIF
# Config of INTIF in bypass mode (see "alcasar-bypass.sh")
	cat <<EOF > /etc/sysconfig/network-scripts/bypass-ifcfg-$INTIF
DEVICE=$INTIF
BOOTPROTO=static
IPADDR=$PRIVATE_IP
NETMASK=$PRIVATE_NETMASK
ONBOOT=yes
METRIC=10
NOZEROCONF=yes
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
EOF
# Mise à l'heure du serveur
	[ -e /etc/ntp/step-tickers.default ] || cp /etc/ntp/step-tickers /etc/ntp/step-tickers.default
	cat <<EOF > /etc/ntp/step-tickers
0.fr.pool.ntp.org	# adapt to your country
1.fr.pool.ntp.org
2.fr.pool.ntp.org
EOF
# Configuration du serveur de temps (sur lui même)
	[ -e /etc/ntp.conf.default ] || cp /etc/ntp.conf /etc/ntp.conf.default
	cat <<EOF > /etc/ntp.conf
server 0.fr.pool.ntp.org	# adapt to your country
server 1.fr.pool.ntp.org
server 2.fr.pool.ntp.org
server 127.127.1.0   		# local clock si NTP internet indisponible ...
fudge 127.127.1.0 stratum 10
restrict $PRIVATE_NETWORK mask $PRIVATE_NETMASK nomodify notrap
restrict 127.0.0.1
driftfile /var/lib/ntp/drift
logfile /var/log/ntp.log
disable monitor
EOF

	chown -R ntp:ntp /var/lib/ntp
# Renseignement des fichiers hosts.allow et hosts.deny
	[ -e /etc/hosts.allow.default ]  || cp /etc/hosts.allow /etc/hosts.allow.default
	cat <<EOF > /etc/hosts.allow
ALL: LOCAL, 127.0.0.1, localhost, $PRIVATE_IP
sshd: ALL
ntpd: $PRIVATE_NETWORK_SHORT
EOF
	[ -e /etc/host.deny.default ]  || cp /etc/hosts.deny /etc/hosts.deny.default
	cat <<EOF > /etc/hosts.deny
ALL: ALL: spawn ( /bin/echo "service %d demandé par %c" | /bin/mail -s "Tentative d'accès au service %d par %c REFUSE !!!" security ) &
EOF
	chmod o+r $DIR_DEST_BIN/alcasar-iptables.sh #lecture possible pour apache (interface php du filtrage réseau)
# create the ip_blocked file with a first line (LAN between ALCASAR and the Internet GW)
	echo "#$PUBLIC_NETWORK/$PUBLIC_PREFIX LAN-ALCASAR-BOX" > $DIR_DEST_ETC/alcasar-ip-blocked
# load conntrack ftp module
	[ -e /etc/modprobe.preload.default ] || cp /etc/modprobe.preload /etc/modprobe.preload.default
	echo "nf_conntrack_ftp" >>  /etc/modprobe.preload
# load ipt_NETFLOW module
	echo "ipt_NETFLOW" >>  /etc/modprobe.preload
# modify iptables service files (start with "alcasar-iptables.sh" and stop with flush)
[ -e /lib/systemd/system/iptables.service.default ] || cp /lib/systemd/system/iptables.service /lib/systemd/system/iptables.service.default
$SED 's/ExecStart=\/usr\/libexec\/iptables.init start/ExecStart=\/usr\/local\/bin\/alcasar-iptables.sh/' /lib/systemd/system/iptables.service
[ -e /usr/libexec/iptables.init.default ] || cp /usr/libexec/iptables.init /usr/libexec/iptables.init.default
$SED "s?\[ -f \$IPTABLES_CONFIG \] .*?#&?" /usr/libexec/iptables.init # comment the test in order the stop function run (fluxh all rules & policies)
# 
# the script "$DIR_DEST_BIN/alcasar-iptables.sh" is launched at the end in order to allow update via ssh
} # End of network ()

##################################################################
##			Function "ACC"				##
## - installation du centre de gestion (ALCASAR Control Center)	##
## - configuration du serveur web (Apache)			##
## - définition du 1er comptes de gestion 			##
## - sécurisation des accès					##
##################################################################
ACC ()
{
	[ -d $DIR_WEB ] && rm -rf $DIR_WEB
	mkdir $DIR_WEB
# Copie et configuration des fichiers du centre de gestion
	cp -rf $DIR_INSTALL/web/* $DIR_WEB/
	echo "$VERSION" > $DIR_WEB/VERSION
	$SED "s?99/99/9999?$DATE_SHORT?g" $DIR_ACC/menu.php
	$SED "s?\$DB_RADIUS = .*?\$DB_RADIUS = \"$DB_RADIUS\"\;?g" $DIR_ACC/phpsysinfo/includes/xml/portail.php
	$SED "s?\$DB_USER = .*?\$DB_USER = \"$DB_USER\"\;?g" $DIR_ACC/phpsysinfo/includes/xml/portail.php
	$SED "s?\$radiuspwd = .*?\$radiuspwd = \"$radiuspwd\"\;?g" $DIR_ACC/phpsysinfo/includes/xml/portail.php
	chmod 640 $DIR_ACC/phpsysinfo/includes/xml/portail.php
	chown -R apache:apache $DIR_WEB/*
# create the backup structure :
# - base = users database
# - archive = tarball of "base + http firewall + netflow"
# - security = watchdog disconnection)
	for i in base archive security;
	do
		[ -d $DIR_SAVE/$i ] || mkdir -p $DIR_SAVE/$i
	done
	chown -R root:apache $DIR_SAVE
# Configuration et sécurisation php
	[ -e /etc/php.ini.default ] || cp /etc/php.ini /etc/php.ini.default
	timezone=`cat /etc/sysconfig/clock|grep ZONE|cut -d"=" -f2`
	$SED "s?^;date.timezone =.*?date.timezone = $timezone?g" /etc/php.ini
	$SED "s?^upload_max_filesize.*?upload_max_filesize = 100M?g" /etc/php.ini
	$SED "s?^post_max_size.*?post_max_size = 100M?g" /etc/php.ini
	$SED "s?^html_errors.*?html_errors = Off?g" /etc/php.ini
	$SED "s?^expose_php.*?expose_php = Off?g" /etc/php.ini
# Configuration et sécurisation Apache
	rm -rf /var/www/cgi-bin/* /var/www/perl/* /var/www/icons/README* /var/www/error/README*
	[ -e /etc/httpd/conf/httpd.conf.default ] || cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.default
	$SED "s?^#ServerName.*?ServerName $HOSTNAME.$DOMAIN?g" /etc/httpd/conf/httpd.conf
	$SED "s?^Listen.*?Listen $PRIVATE_IP:80?g" /etc/httpd/conf/httpd.conf
	$SED "s?Options Indexes.*?Options -Indexes?g" /etc/httpd/conf/httpd.conf
	echo "ServerTokens Prod" >> /etc/httpd/conf/httpd.conf
	echo "ServerSignature Off" >> /etc/httpd/conf/httpd.conf
	[ -e /etc/httpd/conf/modules.d/00_base.conf.default ] || cp /etc/httpd/conf/modules.d/00_base.conf /etc/httpd/conf/modules.d/00_base.conf.default
	$SED "s?^LoadModule authn_anon_module.*?#LoadModule authn_anon_module modules/mod_authn_anon.so?g" /etc/httpd/conf/modules.d/00_base.conf
	$SED "s?^LoadModule status_module.*?#LoadModule status_module modules/mod_status.so?g" /etc/httpd/conf/modules.d/00_base.conf
	$SED "s?^LoadModule info_module.*?#LoadModule info_module modules/mod_info.so?g" /etc/httpd/conf/modules.d/00_base.conf
	$SED "s?^LoadModule imagemap_module.*?#LoadModule imagemap_module modules/mod_imagemap.so?g" /etc/httpd/conf/modules.d/00_base.conf
	$SED "s?^LoadModule rewrite_module.*?#LoadModule rewrite_module modules/mod_rewrite.so?g" /etc/httpd/conf/modules.d/00_base.conf
	$SED "s?^LoadModule speling_module.*?#LoadModule speling_module modules/mod_speling.so?g" /etc/httpd/conf/modules.d/00_base.conf
	[ -e /etc/httpd/conf/conf.d/ssl.conf.default ] || cp /etc/httpd/conf/conf.d/ssl.conf /etc/httpd/conf/conf.d/ssl.conf.default
	echo "Listen $PRIVATE_IP:443" > /etc/httpd/conf/conf.d/ssl.conf # Listen only on INTIF
	echo "SSLProtocol all -SSLv2 -SSLv3" >> /etc/httpd/conf/conf.d/ssl.conf  # exclude vulnerable protocols
	echo "SSLCipherSuite ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS" >> /etc/httpd/conf/conf.d/ssl.conf # Define the cipher suite
	echo "SSLHonorCipherOrder on" >> /etc/httpd/conf/conf.d/ssl.conf # The Browser must respect the order of the cipher suite
	echo "SSLPassPhraseDialog  builtin" >> /etc/httpd/conf/conf.d/ssl.conf # in case of passphrase the dialog will be perform on stdin
	echo "SSLSessionCache \"shmcb:/run/httpd/ssl_scache(512000)\"" >> /etc/httpd/conf/conf.d/ssl.conf # default cache size
	echo "SSLSessionCacheTimeout 300" >> /etc/httpd/conf/conf.d/ssl.conf # default cache time in seconds
# Error page management
[ -e /etc/httpd/conf/conf.d/multilang-errordoc.conf.default ] || cp /etc/httpd/conf/conf.d/multilang-errordoc.conf /etc/httpd/conf/conf.d/multilang-errordoc.conf.default
cat <<EOF > /etc/httpd/conf/conf.d/multilang-errordoc.conf
Alias /error/ "/var/www/html/"
<Directory "/usr/share/httpd/error">
    AllowOverride None
    Options IncludesNoExec
    AddOutputFilter Includes html
    AddHandler type-map var
    Require all granted
    LanguagePriority en cs de es fr it ja ko nl pl pt-br ro sv tr
    ForceLanguagePriority Prefer Fallback
</Directory>
ErrorDocument 400 /error/error.php?error=400
ErrorDocument 401 /error/error.php?error=401
ErrorDocument 403 /error/error.php?error=403
ErrorDocument 404 /error/error.php?error=404
ErrorDocument 405 /error/error.php?error=405
ErrorDocument 408 /error/error.php?error=408
ErrorDocument 410 /error/error.php?error=410
ErrorDocument 411 /error/error.php?error=411
ErrorDocument 412 /error/error.php?error=412
ErrorDocument 413 /error/error.php?error=413
ErrorDocument 414 /error/error.php?error=414
ErrorDocument 415 /error/error.php?error=415
ErrorDocument 500 /error/error.php?error=500
ErrorDocument 501 /error/error.php?error=501
ErrorDocument 502 /error/error.php?error=502
ErrorDocument 503 /error/error.php?error=503
ErrorDocument 506 /error/error.php?error=506
EOF
	[ -e /usr/share/httpd/error/include/top.html.default ] || cp /usr/share/httpd/error/include/top.html /usr/share/httpd/error/include/top.html.default
	$SED "s?background-color.*?background-color: #EFEFEF; }?g" /usr/share/httpd/error/include/top.html
	[ -e /usr/share/httpd/error/include/bottom.html.default ] || cp /usr/share/httpd/error/include/bottom.html /usr/share/httpd/error/include/bottom.html.default
	cat <<EOF > /usr/share/httpd/error/include/bottom.html
</body>
</html>
EOF
# Définition du premier compte lié au profil 'admin'

# !! remove when > V2.9.2 (we need to create new accounts)
# if [ "$mode" = "install" ]
#	then
		header_install
		admin_portal=!
		PTN='^[a-zA-Z0-9-]*$'
		until [[ $(expr $admin_portal : $PTN) -gt 0 ]]
                	do
			header_install
			if [ $Lang == "fr" ]
			then 
				echo ""
				echo "Définissez un premier compte d'administration du portail :"
				echo
				echo -n "Nom : "
			else
				echo ""
				echo "Define the first account allow to administrate the portal :"
				echo
				echo -n "Account : "
			fi
			read admin_portal
			if [ "$admin_portal" == "" ]
				then
				admin_portal=!
			fi
			done
# Creation of keys file for the admin account ("admin")
		[ -d $DIR_DEST_ETC/digest ] && rm -rf $DIR_DEST_ETC/digest
		mkdir -p $DIR_DEST_ETC/digest
		chmod 755 $DIR_DEST_ETC/digest
		until [ -s $DIR_DEST_ETC/digest/key_admin ]
			do
				/usr/bin/htdigest -c $DIR_DEST_ETC/digest/key_admin "ALCASAR Control Center (ACC)" $admin_portal
			done
		$DIR_DEST_SBIN/alcasar-profil.sh --list
# !! remove if > V2.9.2
# fi

# synchronisation horaire
	ntpd -q -g &
# Sécurisation du centre
	rm -f /etc/httpd/conf/webapps.d/alcasar*
	cat <<EOF > /etc/httpd/conf/webapps.d/alcasar.conf
<Directory $DIR_ACC>
	SSLRequireSSL
	AllowOverride None
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	require valid-user
	AuthType digest
	AuthName "ALCASAR Control Center (ACC)" 
	AuthDigestDomain $HOSTNAME.$DOMAIN
	BrowserMatch "MSIE" AuthDigestEnableQueryStringHack=On
	AuthUserFile $DIR_DEST_ETC/digest/key_all
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN/
</Directory>
<Directory $DIR_ACC/admin>
	SSLRequireSSL
	AllowOverride None
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	require valid-user
	AuthType digest
	AuthName "ALCASAR Control Center (ACC)" 
	AuthDigestDomain $HOSTNAME.$DOMAIN
	BrowserMatch "MSIE" AuthDigestEnableQueryStringHack=On
	AuthUserFile $DIR_DEST_ETC/digest/key_admin
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN/
</Directory>
<Directory $DIR_ACC/manager>
	SSLRequireSSL
	AllowOverride None
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	require valid-user
	AuthType digest
	AuthName "ALCASAR Control Center (ACC)" 
	AuthDigestDomain $HOSTNAME.$DOMAIN
	BrowserMatch "MSIE" AuthDigestEnableQueryStringHack=On
	AuthUserFile $DIR_DEST_ETC/digest/key_manager
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN/
</Directory>
<Directory $DIR_ACC/backup>
	SSLRequireSSL
	AllowOverride None
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	require valid-user
	AuthType digest
	AuthName "ALCASAR Control Center (ACC)" 
	AuthDigestDomain $HOSTNAME.$DOMAIN
	BrowserMatch "MSIE" AuthDigestEnableQueryStringHack=On
	AuthUserFile $DIR_DEST_ETC/digest/key_backup
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN/
</Directory>
Alias /save/ "$DIR_SAVE/"
<Directory $DIR_SAVE>
	SSLRequireSSL
	Options Indexes
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	require valid-user
	AuthType digest
	AuthName "ALCASAR Control Center (ACC)" 
	AuthDigestDomain $HOSTNAME.$DOMAIN
	AuthUserFile $DIR_DEST_ETC/digest/key_backup
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN/
</Directory>
EOF
# Launch after coova
$SED "s?^After=.*?After=network.target remote-fs.target nss-lookup.target chilli.service?g" /lib/systemd/system/httpd.service
} # End of ACC ()

##########################################################################################
##				Fonction "CA"						##
## - Création d'une Autorité de Certification et du certificat serveur pour apache 	##
##########################################################################################
CA ()
{
	$DIR_DEST_BIN/alcasar-CA.sh
	FIC_VIRTUAL_SSL=`find /etc/httpd/conf -type f -name *default_ssl_vhost.conf`
	[ -e /etc/httpd/conf/vhosts-ssl.default ]  || cp $FIC_VIRTUAL_SSL /etc/httpd/conf/vhosts-ssl.default
	cat <<EOF > $FIC_VIRTUAL_SSL
# default SSL virtual host, used for all HTTPS requests that do not
# match a ServerName or ServerAlias in any <VirtualHost> block.

<VirtualHost _default_:443>
# general configuration
    ServerAdmin root@localhost
    ServerName $HOSTNAME.$DOMAIN

# SSL configuration
    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/alcasar.crt
    SSLCertificateKeyFile /etc/pki/tls/private/alcasar.key
    SSLCertificateChainFile /etc/pki/tls/certs/server-chain.crt
    CustomLog logs/ssl_request_log \
	"%t %{SSL_PROTOCOL}x %{SSL_CIPHER}x [%h] \"%r\" %b"
    ErrorLog logs/ssl_error_log
    ErrorLogFormat "[%t] [%m:%l] [client %a] %M"
</VirtualHost>
EOF

	chown -R root:apache /etc/pki
	chmod -R 750 /etc/pki
} # End of CA ()

##########################################################################################
##			Fonction "init_db"						##
## - Initialisation de la base Mysql							##
## - Affectation du mot de passe de l'administrateur (root)				##
## - Suppression des bases et des utilisateurs superflus				##
## - Création de la base 'radius'							##
## - Installation du schéma de cette base						##
## - Import des tables de comptabilité (mtotacct, totacct) et info_usagers (userinfo)	##
##       ces table proviennent de 'dialupadmin' (paquetage freeradius-web)		##
##########################################################################################
init_db ()
{
	rm -rf /var/lib/mysql # to be sure that there is no former installation
	[ -e /etc/my.cnf.default ] || cp /etc/my.cnf /etc/my.cnf.default
	$SED "s?^#bind-address.*?bind-address=127.0.0.1?g" /etc/my.cnf
	$SED "s?^tmpdir.*?tmpdir=/tmp?g" /etc/my.cnf
	/usr/bin/systemctl start mysqld.service
	sleep 4
	mysqladmin -u root password $mysqlpwd
	MYSQL="/usr/bin/mysql -uroot -p$mysqlpwd --exec"
# Secure the server
	$MYSQL="DROP DATABASE IF EXISTS test;DROP DATABASE IF EXISTS tmp;"
	$MYSQL="CONNECT mysql;DELETE from user where User='';DELETE FROM user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');FLUSH PRIVILEGES;" 
# Create 'radius' database
	$MYSQL="CREATE DATABASE IF NOT EXISTS $DB_RADIUS;GRANT ALL ON $DB_RADIUS.* TO $DB_USER@localhost IDENTIFIED BY '$radiuspwd';FLUSH PRIVILEGES;"
# Add an empty radius database structure
	mysql -u$DB_USER -p$radiuspwd $DB_RADIUS < $DIR_CONF/radiusd-db-vierge.sql
# modify the start script in order to close accounting connexion when the system is comming down or up
	[ -e /lib/systemd/system/mysqld.service.default ] || cp /lib/systemd/system/mysqld.service /lib/systemd/system/mysqld.service.default
	$SED "/ExecStartPost=/a ExecStop=/usr/local/sbin/alcasar-mysql.sh -acct_stop" /usr/lib/systemd/system/mysqld.service
	$SED "/ExecStartPost=/a ExecStartPost=/usr/local/sbin/alcasar-mysql.sh -acct_stop" /lib/systemd/system/mysqld.service
	/usr/bin/systemctl daemon-reload
} # End of init_db ()

##########################################################################
##			Fonction "radius"				##
## - Paramètrage des fichiers de configuration FreeRadius		##
## - Affectation du secret partagé entre coova-chilli et freeradius	##
## - Modification de fichier de conf pour l'accès à Mysql		##
##########################################################################
radius ()
{
	cp -f $DIR_CONF/radiusd-db-vierge.sql /etc/raddb/
	chown -R radius:radius /etc/raddb
	[ -e /etc/raddb/radiusd.conf.default ] || cp /etc/raddb/radiusd.conf /etc/raddb/radiusd.conf.default
# Set radius.conf parameters
	$SED "s?^[\t ]*#[\t ]*user =.*?user = radius?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*#[\t ]*group =.*?group = radius?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*status_server =.*?status_server = no?g" /etc/raddb/radiusd.conf
# remove the proxy function
	$SED "s?^[\t ]*proxy_requests.*?proxy_requests = no?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*\$INCLUDE proxy.conf.*?#\$INCLUDE proxy.conf?g" /etc/raddb/radiusd.conf
# remove EAP module
	$SED "s?^[\t ]*\$INCLUDE eap.conf.*?#\$INCLUDE eap.conf?g" /etc/raddb/radiusd.conf
# listen on loopback (should be modified later if EAP enabled)
	$SED "s?^[\t ]*ipaddr =.*?ipaddr = 127.0.0.1?g" /etc/raddb/radiusd.conf
# enable the  SQL module (and SQL counter)
	$SED "s?^[\t ]*#[\t ]*\$INCLUDE sql.conf.*?\$INCLUDE sql.conf?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*#[\t ]*\$INCLUDE sql/mysql/counter.conf?\$INCLUDE sql/mysql/counter.conf?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*\$INCLUDE policy.conf?#\$INCLUDE policy.conf?g" /etc/raddb/radiusd.conf
# only include modules for ALCASAR needs
	$SED "s?^[\t ]*\$INCLUDE \${confdir}/modules/.*?\t#\$INCLUDE \${confdir}/modules/\n\t# we only include modules for ALCASAR needs\n\t\$INCLUDE \${confdir}/modules/attr_filter\n\t\$INCLUDE \${confdir}/modules/expiration\n\t\$INCLUDE \${confdir}/modules/logintime\n\t\$INCLUDE \${confdir}/modules/ldap\n\t\$INCLUDE \${confdir}/modules/pap?g" /etc/raddb/radiusd.conf
	$SED "s/^[\t ]exec$/\#\texec/g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*expr.*?\#\texpr?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*\#	daily.*?\#\tdaily\n\tsql?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*logintime.*?\tlogintime\n\tnoresetcounter\n\tdailycounter\n\tmonthlycounter\n\tattr_filter.access_reject\n\tattr_filter.accounting_response\n\tpap?g" /etc/raddb/radiusd.conf
	$SED "s?^[\t ]*\$INCLUDE sites-enabled/.*?\#\$INCLUDE sites-enabled/\n\#\tenable only alcasar virtual server\n\$INCLUDE sites-enabled/alcasar?g" /etc/raddb/radiusd.conf
# remvove virtual server and copy our conf file
	rm -f /etc/raddb/sites-enabled/*
       	cp $DIR_CONF/radius/alcasar-radius /etc/raddb/sites-available/alcasar
	chown radius:apache /etc/raddb/sites-available/alcasar /etc/raddb/modules/ldap # droits rw pour apache (module ldap)
	chmod 660 /etc/raddb/sites-available/alcasar /etc/raddb/modules/ldap
	chgrp apache /etc/raddb /etc/raddb/sites-available /etc/raddb/modules
	ln -s /etc/raddb/sites-available/alcasar /etc/raddb/sites-enabled/alcasar
# Inutile dans notre fonctionnement mais les liens sont recréés par un update de radius ... donc forcé en tant que fichier à 'vide'
	touch /etc/raddb/sites-enabled/{inner-tunnel,control-socket,default}
# client.conf configuration (127.0.0.1 suffit mais on laisse le deuxième client pour la future gestion de l'EAP)
	[ -e /etc/raddb/clients.conf.default ] || cp -f /etc/raddb/clients.conf /etc/raddb/clients.conf.default
	cat << EOF > /etc/raddb/clients.conf
client 127.0.0.1 {
	secret = $secretradius
	shortname = localhost
}
EOF
# sql.conf modification
	[ -e /etc/raddb/sql.conf.default ] || cp /etc/raddb/sql.conf /etc/raddb/sql.conf.default
	$SED "s?^[\t ]*login =.*?login = \"$DB_USER\"?g" /etc/raddb/sql.conf
	$SED "s?^[\t ]*password =.*?password = \"$radiuspwd\"?g" /etc/raddb/sql.conf
	$SED "s?^[\t ]*radius_db =.*?radius_db = \"$DB_RADIUS\"?g" /etc/raddb/sql.conf
	$SED "s?^[\t ]*sqltrace =.*?sqltrace = no?g" /etc/raddb/sql.conf
# dialup.conf modification (case sensitive for username, check simultaneous use, patch on 'postauth' table, etc.) 
	[ -e /etc/raddb/sql/mysql/dialup.conf.default ] || cp /etc/raddb/sql/mysql/dialup.conf /etc/raddb/sql/mysql/dialup.conf.default
	cp -f $DIR_CONF/radius/dialup.conf /etc/raddb/sql/mysql/dialup.conf
# counter.conf modification (change the Max-All-Session-Time counter)
	[ -e /etc/raddb/sql/mysql/counter.conf.default ] || cp /etc/raddb/sql/mysql/counter.conf /etc/raddb/sql/mysql/counter.conf.default
	cp -f $DIR_CONF/radius/counter.conf /etc/raddb/sql/mysql/counter.conf
	chown -R radius:radius /etc/raddb/sql/mysql/*
# make certain that mysql is up before radius start
	[ -e /lib/systemd/system/radiusd.service.default ] || cp /lib/systemd/system/radiusd.service /lib/systemd/system/radiusd.service.default
	$SED "s?^After=.*?After=syslog.target network.target mysqld.service?g" /lib/systemd/system/radiusd.service
	/usr/bin/systemctl daemon-reload
} # End radius ()

##########################################################################
##			Function "radius_web"				##
## - Import, modification et paramètrage de l'interface "dialupadmin"	##
## - Création du lien vers la page de changement de mot de passe        ##
##########################################################################
radius_web ()
{
# copie de l'interface d'origine dans la structure Alcasar
	[ -d /usr/share/freeradius-web ] && cp -rf /usr/share/freeradius-web/* $DIR_ACC/manager/
	rm -f $DIR_ACC/manager/index.html $DIR_ACC/manager/readme 
	rm -f $DIR_ACC/manager/htdocs/about.html $DIR_ACC/manager/htdocs/index.html $DIR_ACC/manager/htdocs/content.html
# copie des fichiers modifiés
	cp -rf $DIR_INSTALL/web/acc/manager/* $DIR_ACC/manager/
	chown -R apache:apache $DIR_ACC/manager/
# Modification des fichiers de configuration
	[ -e /etc/freeradius-web/admin.conf.default ] || cp /etc/freeradius-web/admin.conf /etc/freeradius-web/admin.conf.default
	$SED "s?^general_domain:.*?general_domain: $DOMAIN?g" /etc/freeradius-web/admin.conf
	$SED "s?^sql_username:.*?sql_username: $DB_USER?g" /etc/freeradius-web/admin.conf
	$SED "s?^sql_password:.*?sql_password: $radiuspwd?g" /etc/freeradius-web/admin.conf
	$SED "s?^sql_debug:.*?sql_debug: false?g" /etc/freeradius-web/admin.conf
	$SED "s?^sql_usergroup_table: .*?sql_usergroup_table: radusergroup?g" /etc/freeradius-web/admin.conf
	$SED "s?^sql_password_attribute:.*?sql_password_attribute: Crypt-Password?g" /etc/freeradius-web/admin.conf
	$SED "s?^general_finger_type.*?# general_finger_type: snmp?g" /etc/freeradius-web/admin.conf
	$SED "s?^general_stats_use_totacct.*?general_stats_use_totacct: yes?g" /etc/freeradius-web/admin.conf
	$SED "s?^general_charset.*?general_charset: utf-8?g" /etc/freeradius-web/admin.conf
	[ -e /etc/freeradius-web/config.php.default ] || cp /etc/freeradius-web/config.php /etc/freeradius-web/config.php.default
	cp -f $DIR_CONF/radius/freeradiusweb-config.php /etc/freeradius-web/config.php
	cat <<EOF > /etc/freeradius-web/naslist.conf
nas1_name: alcasar-$ORGANISME
nas1_model: Portail captif
nas1_ip: $PRIVATE_IP
nas1_port_num: 0
nas1_community: public
EOF
# Modification des attributs visibles lors de la création d'un usager ou d'un groupe
	[ -e /etc/freeradius-web/user_edit.attrs.default ] || mv /etc/freeradius-web/user_edit.attrs /etc/freeradius-web/user_edit.attrs.default
	cp -f $DIR_CONF/radius/user_edit.attrs /etc/freeradius-web/user_edit.attrs
# Ajout du mappage des attributs chillispot
	[ -e /etc/freeradius-web/sql.attrmap.default ] || mv /etc/freeradius-web/sql.attrmap /etc/freeradius-web/sql.attrmap.default
	cp -f $DIR_CONF/radius/sql.attrmap /etc/freeradius-web/sql.attrmap
# Modification des attributs visibles sur les pages des statistiques (suppression NAS_IP et NAS_port)
	[ -e /etc/freeradius-web/sql.attrs.default ] || cp /etc/freeradius-web/sql.attrs /etc/freeradius-web/sql.attrs.default
	$SED "s?^NASIPAddress.*?NASIPAddress\tNas IP Address\tno?g" /etc/freeradius-web/sql.attrs
	$SED "s?^NASPortId.*?NASPortId\tNas Port\tno?g" /etc/freeradius-web/sql.attrs
	chown -R apache:apache /etc/freeradius-web
# Ajout de l'alias vers la page de "changement de mot de passe usager"
	cat <<EOF >> /etc/httpd/conf/webapps.d/alcasar.conf
<Directory $DIR_WEB/pass>
	SSLRequireSSL
	AllowOverride None
	Order deny,allow
	Deny from all
	Allow from 127.0.0.1
	Allow from $PRIVATE_NETWORK_MASK
	ErrorDocument 404 https://$HOSTNAME.$DOMAIN
</Directory>
EOF
} # End of radius_web ()

##################################################################################
##			Fonction "chilli"					##
## - Création du fichier d'initialisation et de configuration de coova-chilli	##
## - Paramètrage de la page d'authentification (intercept.php)			##
##################################################################################
chilli ()
{
# chilli unit for systemd
cat << EOF > /lib/systemd/system/chilli.service
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
[Unit]
Description=chilli is a captive portal daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/libexec/chilli start
ExecStop=/usr/libexec/chilli stop
ExecReload=/usr/libexec/chilli reload
PIDFile=/var/run/chilli.pid

[Install]
WantedBy=multi-user.target
EOF
# init file creation
	[ -e /etc/init.d/chilli.default ] || mv /etc/init.d/chilli /etc/init.d/chilli.default
	cat <<EOF > /usr/libexec/chilli
#!/bin/sh
#
# chilli CoovaChilli init
#
# chkconfig: 2345 65 35
# description: CoovaChilli
### BEGIN INIT INFO
# Provides:       chilli
# Required-Start: network 
# Should-Start: 
# Required-Stop:  network
# Should-Stop: 
# Default-Start:  2 3 5
# Default-Stop:
# Description:    CoovaChilli access controller
### END INIT INFO

[ -f /usr/sbin/chilli ] || exit 0
. /etc/init.d/functions
CONFIG=/etc/chilli.conf
pidfile=/var/run/chilli.pid
[ -f \$CONFIG ] || {
    echo "\$CONFIG Not found"
    exit 0
}
RETVAL=0
prog="chilli"
case \$1 in
    start)
	if [ -f \$pidfile ] ; then 
		gprintf "chilli is already running"
	else
        	gprintf "Starting \$prog: "
		rm -f /var/run/chilli* # cleaning
        	/sbin/modprobe tun >/dev/null 2>&1
        	echo 1 > /proc/sys/net/ipv4/ip_forward
		[ -e /dev/net/tun ] || {
	    	(cd /dev; 
			mkdir net; 
			cd net; 
			mknod tun c 10 200)
		}
		ifconfig $INTIF 0.0.0.0
		/usr/sbin/ethtool -K $INTIF gro off
		daemon /usr/sbin/chilli -c \$CONFIG --pidfile=\$pidfile &
        	RETVAL=$?
	fi
	;;

    reload)
	killall -HUP chilli
	;;

    restart)
	\$0 stop
        sleep 2
	\$0 start
	;;
    
    status)
        status chilli
        RETVAL=0
        ;;

    stop)
	if [ -f \$pidfile ] ; then  
        	gprintf "Shutting down \$prog: "
		killproc /usr/sbin/chilli
		RETVAL=\$?
		[ \$RETVAL = 0 ] && rm -f $pidfile
	else	
        	gprintf "chilli is not running"
	fi
	;;
    
    *)
        echo "Usage: \$0 {start|stop|restart|reload|status}"
        exit 1
esac
echo
EOF
chmod a+x /usr/libexec/chilli
# conf file creation
	[ -e /etc/chilli.conf.default ] || cp /etc/chilli.conf /etc/chilli.conf.default
	cat <<EOF > /etc/chilli.conf
# coova config for ALCASAR
cmdsocket	/var/run/chilli.sock
unixipc		chilli.$INTIF.ipc
pidfile		/var/run/chilli.pid
net		$PRIVATE_NETWORK_MASK
dhcpif		$INTIF
ethers		$DIR_DEST_ETC/alcasar-ethers
#nodynip
#statip
dynip		$PRIVATE_NETWORK_MASK
domain		$DOMAIN
dns1		$PRIVATE_IP
dns2		$PRIVATE_IP
uamlisten	$PRIVATE_IP
uamport		3990
macauth
macpasswd	password
strictmacauth
locationname	$HOSTNAME.$DOMAIN
radiusserver1	127.0.0.1
radiusserver2	127.0.0.1
radiussecret	$secretradius
radiusauthport	1812
radiusacctport	1813
uamserver	https://$HOSTNAME.$DOMAIN/intercept.php
radiusnasid	$HOSTNAME.$DOMAIN
uamsecret	$secretuam
uamallowed	$HOSTNAME,$HOSTNAME.$DOMAIN
coaport		3799
conup		$DIR_DEST_BIN/alcasar-conup.sh
condown		$DIR_DEST_BIN/alcasar-condown.sh
include		$DIR_DEST_ETC/alcasar-uamallowed
include		$DIR_DEST_ETC/alcasar-uamdomain
#dhcpgateway		none
#dhcprelayagent		none
#dhcpgatewayport	none
EOF
# create file for DHCP static ip. Reserve the second IP address for INTIF (the first one is for tun0)
	echo "$PRIVATE_MAC $PRIVATE_SECOND_IP" > $DIR_DEST_ETC/alcasar-ethers
# create files for trusted domains and urls
	touch $DIR_DEST_ETC/alcasar-uamallowed $DIR_DEST_ETC/alcasar-uamdomain
	chown root:apache $DIR_DEST_ETC/alcasar-*
	chmod 660 $DIR_DEST_ETC/alcasar-*
# Configuration des fichier WEB d'interception (secret partagé avec coova-chilli)
	$SED "s?^\$uamsecret =.*?\$uamsecret = \"$secretuam\";?g" $DIR_WEB/intercept.php
	$SED "s?^\$userpassword=1.*?\$userpassword=1;?g" $DIR_WEB/intercept.php
# user 'chilli' creation (in order to run conup/off and up/down scripts
	chilli_exist=`grep chilli /etc/passwd|wc -l`
	if [ "$chilli_exist" == "1" ]
	then
	      userdel -r chilli 2>/dev/null
	fi
	groupadd -f chilli
	useradd -r -g chilli -s /bin/false -c "system user for coova-chilli" chilli
}  # End of chilli ()

##################################################################
##		Fonction "dansguardian"				##
## - Paramètrage du gestionnaire de contenu Dansguardian	##
##################################################################
dansguardian ()
{
	mkdir /var/dansguardian
	chown dansguardian /var/dansguardian
	$SED "s?^ExecStart=.*?ExecStart=/usr/sbin/dansguardian -c /etc/dansguardian/dansguardian.conf?g" /lib/systemd/system/dansguardian.service
	$SED "s?^After=.*?After=network.target chilli.service?g" /lib/systemd/system/dansguardian.service
	[ -e $DIR_DG/dansguardian.conf.default ] || cp $DIR_DG/dansguardian.conf $DIR_DG/dansguardian.conf.default
# By default the filter is off 
	$SED "s/^reportinglevel =.*/reportinglevel = 3/g" $DIR_DG/dansguardian.conf
# French deny HTML page
	$SED "s?^language =.*?language = french?g" $DIR_DG/dansguardian.conf
# Listen only on LAN side
	$SED "s?^filterip.*?filterip = $PRIVATE_IP?g" $DIR_DG/dansguardian.conf
# DG send its flow to HAVP
	$SED "s?^proxyport.*?proxyport = 8090?g" $DIR_DG/dansguardian.conf
# replace the default deny HTML page
	cp -f $DIR_CONF/template.html /usr/share/dansguardian/languages/ukenglish/
	cp -f $DIR_CONF/template-fr.html /usr/share/dansguardian/languages/french/template.html
# Don't log
	$SED "s?^loglevel =.*?loglevel = 0?g" $DIR_DG/dansguardian.conf
# on désactive par défaut le controle de contenu des pages html
	$SED "s?^weightedphrasemode =.*?weightedphrasemode = 0?g" $DIR_DG/dansguardian.conf
	cp $DIR_DG/lists/bannedphraselist $DIR_DG/lists/bannedphraselist.default
	$SED "s?^[^#]?#&?g" $DIR_DG/lists/bannedphraselist # (on commente ce qui ne l'est pas)
# on désactive par défaut le contrôle d'URL par expressions régulières
	cp $DIR_DG/lists/bannedregexpurllist $DIR_DG/lists/bannedregexpurllist.default
	$SED "s?^[^#]?#&?g" $DIR_DG/lists/bannedregexpurllist # (on commente ce qui ne l'est pas)

# Configure Dansguardian for large site
# Minimum number of processus to handle connections
	$SED "s?^minchildren =.*?minchildren = 15?g" $DIR_DG/dansguardian.conf
# Maximum number of processus to handle connections
	$SED "s?^maxchildren =.*?maxchildren = 200?g" $DIR_DG/dansguardian.conf
# Run at least 8 daemons
	$SED "s?^minsparechildren =.*?minsparechildren = 8?g" $DIR_DG/dansguardian.conf
# minimum number of processes to spawn
	$SED "s?^preforkchildren =.*?preforkchildren = 10?g" $DIR_DG/dansguardian.conf
# maximum age of a child process before it croaks it
	$SED "s?^maxagechildren =.*?maxagechildren = 1000?g" $DIR_DG/dansguardian.conf
	
# on désactive par défaut le contrôle de téléchargement de fichiers
	[ -e $DIR_DG/dansguardianf1.conf.default ] || cp $DIR_DG/dansguardianf1.conf $DIR_DG/dansguardianf1.conf.default
	$SED "s?^blockdownloads =.*?blockdownloads = off?g" $DIR_DG/dansguardianf1.conf
	[ -e $DIR_DG/lists/bannedextensionlist.default ] || mv $DIR_DG/lists/bannedextensionlist $DIR_DG/lists/bannedextensionlist.default
	[ -e $DIR_DG/lists/bannedmimetypelist.default ] || mv $DIR_DG/lists/bannedmimetypelist $DIR_DG/lists/bannedmimetypelist.default
	touch $DIR_DG/lists/bannedextensionlist
	touch $DIR_DG/lists/bannedmimetypelist
# 'Safesearch' regex actualisation
	$SED "s?images?search?g" $DIR_DG/lists/urlregexplist
# empty LAN IP list that won't be WEB filtered
	[ -e $DIR_DG/lists/exceptioniplist.default ] || mv $DIR_DG/lists/exceptioniplist $DIR_DG/lists/exceptioniplist.default
	touch $DIR_DG/lists/exceptioniplist
# Keep a copy of URL & domain filter configuration files
	[ -e $DIR_DG/lists/bannedsitelist.default ] || mv $DIR_DG/lists/bannedsitelist $DIR_DG/lists/bannedsitelist.default
	[ -e $DIR_DG/lists/bannedurllist.default ] || mv $DIR_DG/lists/bannedurllist $DIR_DG/lists/bannedurllist.default
} # End of dansguardian ()

##################################################################
##			Fonction "antivirus"			##
## - configuration of havp, libclamav and freshclam		##
##################################################################
antivirus ()		
{
# create 'havp' user
	havp_exist=`grep havp /etc/passwd|wc -l`
	if [ "$havp_exist" == "1" ]
	then
	      userdel -r havp 2>/dev/null
	      groupdel havp 2>/dev/null
	fi
	groupadd -f havp
	useradd -r -g havp -s /bin/false -c "system user for havp (antivirus proxy)" havp
	mkdir -p /var/tmp/havp /var/log/havp /var/run/havp
	chown -R havp:havp /var/tmp/havp /var/log/havp /var/run/havp
	[ -e /etc/havp/havp.config.default ] || cp /etc/havp/havp.config /etc/havp/havp.config.default
	$SED "/^REMOVETHISLINE/d" /etc/havp/havp.config
	$SED "s?^# PIDFILE.*?PIDFILE /var/run/havp/havp.pid?g" /etc/havp/havp.config	# pidfile
	$SED "s?^# TRANSPARENT.*?TRANSPARENT false?g" /etc/havp/havp.config		# transparent mode
	$SED "s?^# BIND_ADDRESS.*?BIND_ADDRESS 127.0.0.1?g" /etc/havp/havp.config	# we listen only on loopback
	$SED "s?^# PORT.*?PORT 8090?g" /etc/havp/havp.config				# datas come on port 8090 (on loopback)
	$SED "s?^# TIMEFORMAT.*?TIMEFORMAT %Y %b %d %H:%M:%S?g" /etc/havp/havp.config	# Log format
	$SED "s?^ENABLECLAMLIB.*?ENABLECLAMLIB true?g" /etc/havp/havp.config		# active libclamav AV
	$SED "s?^# LOG_OKS.*?LOG_OKS false?g" /etc/havp/havp.config			# log only when malware matches
	$SED "s?^# SERVERNUMBER.*?SERVERNUMBER 10?g" /etc/havp/havp.config		# 10 daemons are started simultaneously
	$SED "s?^# SCANIMAGES.*?SCANIMAGES false?g" /etc/havp/havp.config		# doesn't scan image files
	$SED "s?^# SKIPMIME.*?SKIPMIME image\/\* video\/\* audio\/\*?g" /etc/havp/havp.config # doesn't scan some multimedia files
# skip checking of youtube flow (too heavy load / risk too low)
	[ -e /etc/havp/whitelist.default ] || cp /etc/havp/whitelist /etc/havp/whitelist.default
	echo "# Whitelist youtube flow" >> /etc/havp/whitelist
	echo "*.youtube.com/*" >> /etc/havp/whitelist
# adapt init script and systemd unit
	[ -e /etc/init.d/havp.default ] || cp /etc/init.d/havp /etc/init.d/havp.default
	cp -f $DIR_CONF/havp-init /etc/init.d/havp
	[ -e /lib/systemd/system/havp.service.default ] || cp /lib/systemd/system/havp.service /lib/systemd/system/havp.service.default
	$SED "/^PIDFile/i ExecStartPre=/bin/mkdir -p /var/run/havp" /lib/systemd/system/havp.service
	$SED "/^PIDFile/i ExecStartPre=/bin/chown -R havp:havp /var/run/havp /var/log/havp" /lib/systemd/system/havp.service
# replace of the intercept page (template)
	cp -f $DIR_CONF/virus-fr.html /etc/havp/templates/fr/virus.html
	cp -f $DIR_CONF/virus-en.html /etc/havp/templates/en/virus.html
# update virus database every 4 hours (24h/6)
	[ -e /etc/freshclam.conf.default ] || cp /etc/freshclam.conf /etc/freshclam.conf.default
	$SED "s?^Checks.*?Checks 6?g" /etc/freshclam.conf
	$SED "s?^NotifyClamd.*?# NotifyClamd /etc/clamd.conf?g" /etc/freshclam.conf
	$SED "/^DatabaseMirror/i DatabaseMirror db.fr.clamav.net" /etc/freshclam.conf
	$SED "/^DatabaseMirror db.fr.clamav.net/i DatabaseMirror switch.clamav.net" /etc/freshclam.conf
	$SED "s?MaxAttempts.*?MaxAttempts 3?g" /etc/freshclam.conf
# update now
	/usr/bin/freshclam --no-warnings
} # End of antivirus ()

##########################################################################
##			Fonction "tinyproxy"				##
## - configuration of tinyproxy (proxy between filterde users and havp)	##
##########################################################################
tinyproxy ()		
{
	tinyproxy_exist=`grep tinyproxy /etc/passwd|wc -l`
	if [ "$tinyproxy_exist" == "1" ]
	then
	      userdel -r tinyproxy 2>/dev/null
	      groupdel tinyproxy 2>/dev/null
	fi
	groupadd -f tinyproxy
	useradd -r -g tinyproxy -s /bin/false -c "system user for tinyproxy" tinyproxy
	mkdir -p /var/run/tinyproxy /var/log/tinyproxy
	chown -R tinyproxy.tinyproxy /var/run/tinyproxy /var/log/tinyproxy
	[ -e /etc/tinyproxy/tinyproxy.conf.default ] || cp /etc/tinyproxy/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf.default
	$SED "s?^User.*?User tinyproxy?g" /etc/tinyproxy/tinyproxy.conf
	$SED "s?^Group.*?Group tinyproxy?g" /etc/tinyproxy/tinyproxy.conf
	$SED "s?^Port.*?Port 8090?g" /etc/tinyproxy/tinyproxy.conf			# Listen Port
	$SED "s?^#Listen.*?Listen $PRIVATE_IP?g" /etc/tinyproxy/tinyproxy.conf		# Listen NIC (only intif)
	$SED "s?^#LogFile.*?LogFile \"/var/log/tinyproxy/tinyproxy.log\"?g" /etc/tinyproxy/tinyproxy.conf
	$SED "s?^#PidFile.*?PidFile \"/var/run/tinyproxy/tinyproxy.pid\"?g" /etc/tinyproxy/tinyproxy.conf
	$SED "s?^LogLevel.*?LogLevel Error?g" /etc/tinyproxy/tinyproxy.conf		# Only errors are logged
	$SED "s?^#Upstream.*?Upstream 127.0.0.1:8090?g" /etc/tinyproxy/tinyproxy.conf	# forward to HAVP
	$SED "s?^#DisableViaHeader.*?DisableViaHeader Yes?g" /etc/tinyproxy/tinyproxy.conf	# Stealth mode
	$SED "s?^Allow.*?Allow $PRIVATE_NETWORK_MASK?g" /etc/tinyproxy/tinyproxy.conf	# Allow from LAN
# Create the systemd unit
cat << EOF > /lib/systemd/system/tinyproxy.service
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# This unit launches tinyproxy (a very light proxy).
# The "sleep 2" is needed because the pid file isn't ready for systemd
[Unit]
Description=Tinyproxy Web Proxy Server
After=network.target iptables.service

[Service]
Type=forking
ExecStartPre=/bin/chown -R tinyproxy.tinyproxy /var/run/tinyproxy /var/log/tinyproxy
ExecStartPre=/bin/sleep 2
PIDFile=/var/run/tinyproxy/tinyproxy.pid
ExecStart=/usr/sbin/tinyproxy -c /etc/tinyproxy/tinyproxy.conf

[Install]
WantedBy=multi-user.target
EOF

} # end of tinyproxy
##################################################################################
##			function "ulogd"					##
## - Ulog config for multi-log files 						##
##################################################################################
ulogd ()
{
# Three instances of ulogd (three different logfiles)
	[ -d /var/log/firewall ] || mkdir -p /var/log/firewall
	nl=1
	for log_type in traceability ssh ext-access
	do
		[ -e /lib/systemd/system/ulogd-$log_type.service ] || cp -f /lib/systemd/system/ulogd.service /lib/systemd/system/ulogd-$log_type.service
		[ -e /var/log/firewall/$log_type.log ] || echo "" > /var/log/firewall/$log_type.log
		cp -f $DIR_CONF/ulogd-sample.conf /etc/ulogd-$log_type.conf
		$SED "s?^group=.*?group=$nl?g" /etc/ulogd-$log_type.conf
		if [ "$ARCH" == "i586" ]; then $SED "s/lib64/lib/g" /etc/ulogd-$log_type.conf; fi
		cat << EOF >> /etc/ulogd-$log_type.conf
[emu1]
file="/var/log/firewall/$log_type.log"
sync=1
EOF
		$SED "s?^ExecStart=.*?ExecStart=/usr/sbin/ulogd -u ulogd -c /etc/ulogd-$log_type.conf $ULOGD_OPTIONS?g" /lib/systemd/system/ulogd-$log_type.service
		nl=`expr $nl + 1`
	done
	chown -R root:apache /var/log/firewall
	chmod 750 /var/log/firewall
	chmod 640 /var/log/firewall/*
}  # End of ulogd ()


##########################################################
##              Function "nfsen"			##
## - install the nfsen grapher				##
## - install the two plugins porttracker & surfmap	##
##########################################################
nfsen()
{
	tar xzf ./conf/nfsen/nfsen-1.3.7.tar.gz -C /tmp/
# Add PortTracker plugin
	for i in /var/www/html/acc/manager/nfsen/plugins /var/log/netflow/porttracker /usr/share/nfsen/plugins
	do
	[ ! -d $i ] && mkdir -p $i && chown -R apache:apache $i
	done
	$SED "s?^my \$PORTSDBDIR =.*?my \$PORTSDBDIR = \"/var/log/netflow/porttracker\";?g" /tmp/nfsen-1.3.7/contrib/PortTracker/PortTracker.pm
# use of our conf file and init unit
	cp $DIR_CONF/nfsen/nfsen.conf /tmp/nfsen-1.3.7/etc/
# Installation of nfsen (we change a little 'install.pl in order not to ask the user for the perl version)
	DirTmp=$(pwd)
	cd /tmp/nfsen-1.3.7/
	/usr/bin/perl install.pl etc/nfsen.conf
	/usr/bin/perl install.pl etc/nfsen.conf # to avoid a Perl mistake "Semaphore introuvable"
# Create RRD DB for porttracker (only in it still doesn't exist)
	cp contrib/PortTracker/PortTracker.pm /usr/share/nfsen/plugins/
	cp contrib/PortTracker/PortTracker.php /var/www/html/acc/manager/nfsen/plugins/
	if [ "$(ls -A "/var/log/netflow/porttracker" 2>&1)" = "" ]; then sudo -u apache nftrack -I -d /var/log/netflow/porttracker; else echo "RRD DB already exists"; fi
	chmod -R 770 /var/log/netflow/porttracker
# nfsen unit for systemd
cat << EOF > /lib/systemd/system/nfsen.service
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# This unit launches nfsen (a Netflow grapher).
[Unit]
Description= NfSen init script
After=network.target iptables.service

[Service]
Type=oneshot
RemainAfterExit=yes
PIDFile=/var/run/nfsen/nfsen.pid
ExecStartPre=/bin/mkdir -p /var/run/nfsen
ExecStartPre=/bin/chown apache:apache /var/run/nfsen
ExecStart=/usr/bin/nfsen start 
ExecStop=/usr/bin/nfsen stop
ExecReload=/usr/bin/nfsen restart
TimeoutSec=0

[Install]
WantedBy=multi-user.target
EOF
# Add the listen port to collect netflow packet (nfcapd)
$SED "s?'\$ziparg $extensions.*?\$ziparg $extensions -b 127.0.0.1;'?g" /usr/libexec/NfSenRC.pm 
# expire delay for the profile "live"
	/usr/bin/systemctl start nfsen
	/bin/nfsen -m live -e 62d 2>/dev/null
# add SURFmap plugin
	cp $DIR_CONF/nfsen/SURFmap_v3.3.1.tar.gz /tmp/
	cp $DIR_CONF/nfsen/GeoLiteCity* /tmp/
	tar xzf /tmp/SURFmap_v3.3.1.tar.gz -C /tmp/
	cd /tmp/
	/usr/bin/sh SURFmap/install.sh
chown -R apache:apache /var/www/html/acc/manager/nfsen /usr/share/nfsen
# clear the installation
	cd $DirTmp
	rm -rf /tmp/nfsen*
	rm -rf /tmp/SURFmap*
} # End of nfsen ()

##################################################
##		Function "vnstat"		##
## Initialization of Vnstat and vnstat phpFE    ##
##################################################
vnstat ()
{
	 [ -e /etc/vnstat.conf.default ] || cp /etc/vnstat.conf /etc/vnstat.conf.default
	 $SED "s?Interface.*?Interface \"$EXTIF\"?g" /etc/vnstat.conf
	 [ -e $DIR_ACC/manager/stats/config.php.default ] || cp $DIR_ACC/manager/stats/config.php $DIR_ACC/manager/stats/config.php.default
	 $SED "s?\$iface_list =.*?\$iface_list = array('$EXTIF');?g" $DIR_ACC/manager/stats/config.php
	/usr/bin/vnstat -u -i $EXTIF
} # End of vnstat	
##################################################
##		Function "dnsmasq"		##
##################################################
dnsmasq ()
{
	[ -d /var/log/dnsmasq ] || mkdir /var/log/dnsmasq
	[ -e /etc/sysconfig/dnsmasq.default ] || cp /etc/sysconfig/dnsmasq /etc/sysconfig/dnsmasq.default
	$SED "s?^OPTION=.*?OPTION=-C /etc/dnsmasq.conf?g" /etc/sysconfig/dnsmasq # default conf file for the first dnsmasq instance
	[ -e /etc/dnsmasq.conf.default ] || cp /etc/dnsmasq.conf /etc/dnsmasq.conf.default
# 1st dnsmasq listen on udp 53 ("dnsmasq - forward"). It's used as dhcp server only if "alcasar-bypass" is on.
	cat << EOF > /etc/dnsmasq.conf 
# Configuration file for "dnsmasq in forward mode"
conf-file=$DIR_DEST_ETC/alcasar-dns-name	# local DNS resolutions
listen-address=$PRIVATE_IP
pid-file=/var/run/dnsmasq.pid
listen-address=127.0.0.1
no-dhcp-interface=$INTIF
no-dhcp-interface=tun0
no-dhcp-interface=lo
bind-interfaces
cache-size=2048
domain=$DOMAIN
domain-needed
expand-hosts
bogus-priv
filterwin2k
server=$DNS1
server=$DNS2
# DHCP service is configured. It will be enabled in "bypass" mode
#dhcp-range=$PRIVATE_FIRST_IP,$PRIVATE_LAST_IP,$PRIVATE_NETMASK,12h
#dhcp-option=option:router,$PRIVATE_IP
#dhcp-option=option:ntp-server,$PRIVATE_IP

# Exemple of static dhcp assignation : <@MAC>,<name>,<@IP>,<MASK>,<ttl bail>
#dhcp-host=11:22:33:44:55:66,ssic-test,192.168.182.20,255.255.255.0,45m
EOF
# 2nd dnsmasq listen on udp 54 ("dnsmasq with blacklist")
	cat << EOF > /etc/dnsmasq-blacklist.conf 
# Configuration file for "dnsmasq with blacklist"
# Add Toulouse blacklist domains
conf-file=$DIR_DEST_ETC/alcasar-dns-name	# local DNS resolutions
conf-dir=$DIR_DEST_SHARE/dnsmasq-bl-enabled
pid-file=/var/run/dnsmasq-blacklist.pid
listen-address=$PRIVATE_IP
port=54
no-dhcp-interface=$INTIF
no-dhcp-interface=tun0
no-dhcp-interface=lo
bind-interfaces
cache-size=2048
domain=$DOMAIN
domain-needed
expand-hosts
bogus-priv
filterwin2k
server=$DNS1
server=$DNS2
EOF
# 3rd dnsmasq listen on udp 55 ("dnsmasq with whitelist")
	cat << EOF > /etc/dnsmasq-whitelist.conf 
# Configuration file for "dnsmasq with whitelist"
# Inclusion de la whitelist <domains> de Toulouse dans la configuration
conf-file=$DIR_DEST_ETC/alcasar-dns-name	# local DNS resolutions
conf-dir=$DIR_DEST_SHARE/dnsmasq-wl-enabled
pid-file=/var/run/dnsmasq-whitelist.pid
listen-address=$PRIVATE_IP
port=55
no-dhcp-interface=$INTIF
no-dhcp-interface=tun0
no-dhcp-interface=lo
bind-interfaces
cache-size=1024
domain=$DOMAIN
domain-needed
expand-hosts
bogus-priv
filterwin2k
address=/#/$PRIVATE_IP				# for Domain name without local resolution (WL)  
ipset=/#/whitelist_ip_allowed			# dynamicly add the resolv IP address in the Firewall rules
EOF
# 4th dnsmasq listen on udp 56 ("blackhole")
	cat << EOF > /etc/dnsmasq-blackhole.conf 
# Configuration file for "dnsmasq as a blackhole"
conf-file=$DIR_DEST_ETC/alcasar-dns-name	# local DNS resolutions
address=/#/$PRIVATE_IP				# redirect all on ALCASAR IP address
pid-file=/var/run/dnsmasq-blackhole.pid
listen-address=$PRIVATE_IP
port=56
no-dhcp-interface=$INTIF
no-dhcp-interface=tun0
no-dhcp-interface=lo
bind-interfaces
cache-size=256
domain=$DOMAIN
domain-needed
expand-hosts
bogus-priv
filterwin2k
EOF

# the main instance should start after network and chilli (which create tun0)
	[ -e /lib/systemd/system/dnsmasq.service.default ] || cp -f /lib/systemd/system/dnsmasq.service /lib/systemd/system/dnsmasq.service.default
	$SED "s?^After=.*?After=syslog.target network-online.target chilli.service?g" /lib/systemd/system/dnsmasq.service
# Create dnsmasq-blacklist, dnsmasq-whitelist and dnsmasq-blackhole unit
	for list in blacklist whitelist blackhole
	do
		cp -f /lib/systemd/system/dnsmasq.service /lib/systemd/system/dnsmasq-$list.service
		$SED "s?^ExecStart=.*?ExecStart=/usr/sbin/dnsmasq -C /etc/dnsmasq-$list.conf?g" /lib/systemd/system/dnsmasq-$list.service
		$SED "s?^PIDFile=.*?PIDFile=/var/run/dnsmasq-$list.pid?g" /lib/systemd/system/dnsmasq-$list.service
	done
} # End dnsmasq

##########################################################
##		Fonction "BL"				##
##########################################################
BL ()
{
# copy and extract toulouse BL
	rm -rf $DIR_DG/lists/blacklists
	tar zxf $DIR_CONF/blacklists.tar.gz --directory=$DIR_DG/lists/ > /dev/null 2>&1
# creation of the OSSI BL and WL categories (domain name and url)
	mkdir $DIR_DG/lists/blacklists/ossi
	touch $DIR_DG/lists/blacklists/ossi/domains $DIR_DG/lists/blacklists/ossi/domains_wl
	touch $DIR_DG/lists/blacklists/ossi/urls $DIR_DG/lists/blacklists/ossi/urls_wl
	chown -R dansguardian:apache $DIR_DG $DIR_DEST_SHARE
	chmod -R g+rw $DIR_DG $DIR_DEST_SHARE
# creation of file for the rehabilited domains and urls
	[ -e $DIR_DG/lists/exceptionsitelist.default ] || mv $DIR_DG/lists/exceptionsitelist $DIR_DG/lists/exceptionsitelist.default
	[ -e $DIR_DG/lists/exceptionurllist.default ] || mv $DIR_DG/lists/exceptionurllist $DIR_DG/lists/exceptionurllist.default
	touch $DIR_DG/lists/exceptionsitelist
	touch $DIR_DG/lists/exceptionurllist
# On crée la configuration de base du filtrage de domaine et d'URL pour Dansguardian
	cat <<EOF > $DIR_DG/lists/bannedurllist
# Dansguardian filter config for ALCASAR
EOF
	cat <<EOF > $DIR_DG/lists/bannedsitelist
# Dansguardian domain filter config for ALCASAR
# block all sites except those in the exceptionsitelist --> liste blanche (désactivée)
#**
# block all SSL and CONNECT tunnels
**s
# block all SSL and CONNECT tunnels specified only as an IP
*ips
# block all sites specified only by an IP
*ip
EOF
# Add Bing and Youtube to the safesearch url regext list (parental control)
	cat <<EOF >> $DIR_DG/lists/urlregexplist
# Bing - add 'adlt=strict'
#"(^http://[0-9a-z]+\.bing\.[a-z]+[-/%.0-9a-z]*\?)(.*)"->"\1\2&adlt=strict"
# Youtube - add 'edufilter=your_ID' 
#"(^http://[0-9a-z]+\.youtube\.[a-z]+[-/%.0-9a-z]*\?)(.*)"->"\1\2&edufilter=ABCD1234567890abcdef"
EOF
# change the the google safesearch ("safe=strict" instead of "safe=vss")
	$SED "s?safe=vss?safe=strict?g" $DIR_DG/lists/urlregexplist
# adapt the BL to ALCASAR architecture. Enable the default categories
	if [ "$mode" != "update" ]; then
		$DIR_DEST_SBIN/alcasar-bl.sh --adapt
		$DIR_DEST_SBIN/alcasar-bl.sh --cat_choice
	fi
}

##########################################################
##		Fonction "cron"				##
## - Mise en place des différents fichiers de cron	##
##########################################################
cron ()
{
# Modif du fichier 'crontab' pour passer les cron à minuit au lieu de 04h00
	[ -e /etc/crontab.default ] || cp /etc/crontab /etc/crontab.default
	cat <<EOF > /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/

# run-parts
01 * * * * root nice -n 19 run-parts --report /etc/cron.hourly
02 0 * * * root nice -n 19 run-parts --report /etc/cron.daily
22 0 * * 0 root nice -n 19 run-parts --report /etc/cron.weekly
42 0 1 * * root nice -n 19 run-parts --report /etc/cron.monthly
EOF
	[ -e /etc/anacrontab.default ] || cp /etc/anacrontab /etc/anacrontab.default
	cat <<EOF >> /etc/anacrontab
7       8       cron.MysqlDump          nice /etc/cron.d/alcasar-mysql
7       10      cron.logExport          nice /etc/cron.d/alcasar-archive
7	20	cron.importClean	nice /etc/cron.d/alcasar-clean_import
EOF

	cat <<EOF > /etc/cron.d/alcasar-mysql
# Contrôle, réparation et export de la base des usagers (tous les lundi à 4h45)
45 4 * * 1 root $DIR_DEST_SBIN/alcasar-mysql.sh --dump
# Nettoyage des utilisateurs dont la date d'expiration du compte est supérieure à 7 jours
40 4 * * * root /usr/local/sbin/alcasar-mysql.sh --expire_user 2>&1 >/dev/null
EOF
	cat <<EOF > /etc/cron.d/alcasar-archive
# Archive des logs et de la base de données (tous les lundi à 5h35)
35 5 * * 1 root $DIR_DEST_BIN/alcasar-archive.sh --now
EOF
	cat << EOF > /etc/cron.d/alcasar-ticket-clean
# suppression des fichiers de mots de passe (imports massifs par fichier) et des ticket PDF d'utilisateur
30 * * * *  root $DIR_DEST_BIN/alcasar-ticket-clean.sh
EOF
	cat << EOF > /etc/cron.d/alcasar-distrib-updates
# mise à jour automatique de la distribution tous les jours 3h30
30 3 * * *  root /usr/sbin/urpmi --auto-update --auto 2>&1
EOF

# mise à jour des stats de connexion (accounting). Scripts provenant de "dialupadmin" (rpm freeradius-web) (cf. wiki.freeradius.org/Dialup_admin).
# on écrase le crontab d'origine installé par le RPM "freeradius-web" (bug remonté à qa.mandriva.com : 46739).
# 'tot_stats' (tout les jours à 01h01) : aggrégat des connexions journalières par usager (renseigne la table 'totacct') 
# 'monthly_tot_stat' (tous les jours à 01h05) : aggrégat des connexions mensuelles par usager (renseigne la table 'mtotacct')
# 'truncate_raddact' (tous les 1er du mois à 01h10) : supprime les entrées journalisées plus vieilles que '$back_days' jours (défini ci-après)
# 'clean_radacct' (tous les 1er du mois à 01h15) : ferme les session ouvertes de plus de '$back_days' jours (défini ci-après)
	$SED "s?^\$back_days.*?\$back_days = 365;?g" /usr/bin/truncate_radacct
	$SED "s?^\$back_days.*?\$back_days = 30;?g" /usr/bin/clean_radacct
	rm -f /etc/cron.daily/freeradius-web
	rm -f /etc/cron.monthly/freeradius-web
	cat << EOF > /etc/cron.d/freeradius-web
1 1 * * * root /usr/bin/tot_stats > /dev/null 2>&1
5 1 * * * root /usr/bin/monthly_tot_stats > /dev/null 2>&1
10 1 1 * * root /usr/bin/truncate_radacct > /dev/null 2>&1
15 1 1 * * root /usr/bin/clean_radacct > /dev/null 2>&1
EOF
	cat << EOF > /etc/cron.d/alcasar-watchdog
# activation du "chien de garde" (watchdog) toutes les 3'
*/3 * * * * root $DIR_DEST_BIN/alcasar-watchdog.sh > /dev/null 2>&1
EOF
# activation du "chien de garde des services" (watchdog) toutes les 18'
	cat << EOF > /etc/cron.d/alcasar-daemon-watchdog
# activation du "chien de garde" (daemon-watchdog) toutes les 18'
*/18 * * * * root $DIR_DEST_BIN/alcasar-daemon.sh > /dev/null 2>&1
EOF
# suppression des crons usagers
	rm -f /var/spool/cron/*
} # End cron

##################################################################
## 			Fonction "Fail2Ban"			##
##- Modification de la configuration de fail2ban		##
##- Sécurisation DDOS, SSH-Brute-Force, Intercept.php ...	##
##################################################################
fail2ban()
{
	$DIR_CONF/fail2ban.sh
# Autorise la lecture seule 2 des 3 fichiers de log concernés, havp est traité dans le script d'init de havp
	[ -e /var/log/fail2ban.log ] || touch /var/log/fail2ban.log
	[ -e /var/Save/security/watchdog.log ] || touch /var/Save/security/watchdog.log
	chmod 644 /var/log/fail2ban.log
	chmod 644 /var/Save/security/watchdog.log
	/usr/bin/touch /var/log/auth.log
# fail2ban unit
[ -e /lib/systemd/system/fail2ban.service.default ] || cp /lib/systemd/system/fail2ban.service /lib/systemd/system/fail2ban.service.default
$SED '/ExecStart=/a\ExecStop=/usr/bin/fail2ban-client stop' /usr/lib/systemd/system/fail2ban.service
$SED '/Type=/a\PIDFile=/var/run/fail2ban/fail2ban.pid' /usr/lib/systemd/system/fail2ban.service
$SED '/After=*/c After=syslog.target network.target httpd.service' /usr/lib/systemd/system/fail2ban.service
} #Fin de fail2ban_install()

##################################################################
## 			Fonction "gammu_smsd"			##
## - Creation de la base de donnée Gammu			##
## - Creation du fichier de config: gammu_smsd_conf		##
##								##
##################################################################
gammu_smsd()
{
# Create 'gammu' databse
MYSQL="/usr/bin/mysql -uroot -p$mysqlpwd --exec"
	$MYSQL="CREATE DATABASE IF NOT EXISTS $DB_GAMMU;GRANT ALL ON $DB_GAMMU.* TO $DB_USER@localhost IDENTIFIED BY '$radiuspwd';FLUSH PRIVILEGES"
# Add a gammu database structure
	mysql -u$DB_USER -p$radiuspwd $DB_GAMMU < $DIR_CONF/gammu-smsd-db-vierge.sql

# config file for the daemon
cat << EOF > /etc/gammu_smsd_conf
[gammu]
port = /dev/ttyUSB0
connection = at115200

;########################################################

[smsd]

PIN = 1234

logfile = /var/log/gammu-smsd/gammu-smsd.log
logformat = textall
debuglevel = 0

service = sql
driver = native_mysql
user = $DB_USER
password = $radiuspwd
pc = localhost
database = $DB_GAMMU

RunOnReceive = /usr/local/bin/alcasar-sms.sh --new_sms

StatusFrequency = 30
;LoopSleep = 2

;ResetFrequency = 300
;HardResetFrequency = 120

CheckSecurity = 1 
CheckSignal = 1
CheckBattery = 0
EOF

chmod 755 /etc/gammu_smsd_conf

#Creation dossier de log Gammu-smsd
[ -e /var/log/gammu-smsd ] || mkdir /var/log/gammu-smsd
chmod 755 /var/log/gammu-smsd

#Edition du script sql gammu <-> radius
$SED "s/^u_db=\".*/u_db=\"$DB_USER\"/g" $DIR_DEST_BIN/alcasar-sms.sh
$SED "s/^p_db=\".*/p_db=\"$radiuspwd\"/g" $DIR_DEST_BIN/alcasar-sms.sh

#Création de la règle udev pour les Huawei // idVendor: 12d1
cat << EOF > /etc/udev/rules.d/66-huawei.rules
KERNEL=="ttyUSB0",ATTRS{idVendor}=="12d1",RUN+="/usr/local/bin/alcasar-sms.sh --mode"
EOF

} # END gammu_smsd()

##################################################################
##			Fonction "post_install"			##
## - Modification des bannières (locales et ssh) et des prompts ##
## - Installation de la structure de chiffrement pour root	##
## - Mise en place du sudoers et de la sécurité sur les fichiers##
## - Mise en place du la rotation des logs			##
## - Configuration dans le cas d'une mise à jour		##
##################################################################
post_install()
{
# création de la bannière locale
	[ -e /etc/mageia-release.default ]  || cp /etc/mageia-release /etc/mageia-release.default
	cp -f $DIR_CONF/banner /etc/mageia-release
	echo " V$VERSION" >> /etc/mageia-release
# création de la bannière SSH
	cp /etc/mageia-release /etc/ssh/alcasar-banner-ssh
	chmod 644 /etc/ssh/alcasar-banner-ssh ; chown root:root /etc/ssh/alcasar-banner-ssh
	[ -e /etc/ssh/sshd_config.default ] || cp /etc/ssh/sshd_config /etc/ssh/sshd_config.default
	$SED "s?^Banner.*?Banner /etc/ssh/alcasar-banner-ssh?g" /etc/ssh/sshd_config
	$SED "s?^#Banner.*?Banner /etc/ssh/alcasar-banner-ssh?g" /etc/ssh/sshd_config
# postfix banner anonymisation
	$SED "s?^smtpd_banner =.*?smtpd_banner = $myhostname ESMTP?g" /etc/postfix/main.cf
# sshd écoute côté LAN et WAN
	$SED "s?^#ListenAddress 0\.0\.0\.0.*?ListenAddress 0\.0\.0\.0?g" /etc/ssh/sshd_config
# sshd autorise les connections root par certificat
	$SED "s?^PermitRootLogin.*?PermitRootLogin without-password?g" /etc/ssh/sshd_config
	# Put the default values in conf file
	echo "SSH=off" >> $CONF_FILE
	echo "SSH_ADMIN_FROM=0.0.0.0/0.0.0.0" >> $CONF_FILE
	echo "LDAP=off" >> $CONF_FILE
	echo "LDAP_IP=0.0.0.0/0.0.0.0" >> $CONF_FILE
	echo "YOUTUBE_ID=ABCD1234567890abcdef" >> $CONF_FILE
	echo "MULTIWAN=off" >> $CONF_FILE
	echo "FAILOVER=30" >> $CONF_FILE
	echo "## WANx=active,@IPx/mask,GWx,Weight,MTUx" >> $CONF_FILE
	echo "#WAN1=\"1,$EXTIF:1,192.168.2.20/24,192.168.2.6,1,1500\"" >> $CONF_FILE
	echo "#WAN2=\"1,$EXTIF:2,192.168.3.20/24,192.168.3.1,2,1500\"" >> $CONF_FILE
# Coloration des prompts
	[ -e /etc/bashrc.default ]  || cp /etc/bashrc /etc/bashrc.default
	cp -f $DIR_CONF/bashrc /etc/. ; chmod 644 /etc/bashrc ; chown root:root /etc/bashrc
	$SED "s?^ORGANISME.*?ORGANISME=$ORGANISME?g" /etc/bashrc
# Droits d'exécution pour utilisateur apache et sysadmin
	[ -e /etc/sudoers.default ]  || cp /etc/sudoers /etc/sudoers.default
	cp -f $DIR_CONF/sudoers /etc/. ; chmod 440 /etc/sudoers ; chown root:root /etc/sudoers
	$SED "s?^Host_Alias.*?Host_Alias	LAN_ORG=$PRIVATE_NETWORK/$PRIVATE_NETMASK,localhost		#réseau de l'organisme?g" /etc/sudoers
# Modify some logrotate files (gammu, ulogd)
	cp -f $DIR_CONF/logrotate.d/* /etc/logrotate.d/
	chmod 644 /etc/logrotate.d/*
# rectification sur versions précédentes de la compression des logs
	$SED "s?^delaycompress.*?#&?g" /etc/logrotate.conf
# actualisation des fichiers logs compressés
	for dir in firewall dansguardian httpd
	do
	      find /var/log/$dir -type f -name *.log-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] -exec gzip {} \;
	done
# create the alcasar-load_balancing unit
	cat << EOF > /lib/systemd/system/alcasar-load_balancing.service
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

# This unit lauches alcasar-load-balancing.sh script.
[Unit]
Description=alcasar-load_balancing.sh execution
After=network.target iptables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/alcasar-load_balancing.sh start
ExecStop=/usr/local/sbin/alcasar-load_balancing.sh stop
TimeoutSec=0
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
# processes launched at boot time (Systemctl)
	for i in alcasar-load_balancing mysqld httpd ntpd iptables dnsmasq dnsmasq-blacklist dnsmasq-whitelist dnsmasq-blackhole radiusd nfsen dansguardian freshclam ulogd-ssh ulogd-traceability ulogd-ext-access chilli fail2ban havp tinyproxy vnstat
	do
		/usr/bin/systemctl -q enable $i.service
	done
	
# disable processes at boot time (Systemctl)
	for i in ulogd
	do
		/usr/bin/systemctl -q disable $i.service
	done
	
# Apply French Security Agency (ANSSI) rules
# ignore ICMP broadcast (smurf attack)
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" > /etc/sysctl.d/alcasar.conf
# ignore ICMP errors bogus
	echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/alcasar.conf
# remove ICMP redirects responces
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/alcasar.conf
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/alcasar.conf
# enable SYN Cookies (Syn flood attacks)
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/alcasar.conf
# enable kernel antispoofing
	echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/alcasar.conf
# ignore source routing
	echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/alcasar.conf
# set conntrack timer to 1h (3600s) instead of 5 weeks
	echo "net.netfilter.nf_conntrack_tcp_timeout_established = 3600" >> /etc/sysctl.d/alcasar.conf
# disable log_martians (ALCASAR is often installed between two private network addresses) 
	echo "net.ipv4.conf.all.log_martians = 0" >> /etc/sysctl.d/alcasar.conf
# disable iptables_helpers
	echo "net.netfilter.nf_conntrack_helper = 0" >> /etc/sysctl.d/alcasar.conf
# remove Magic SysReq Keys
	[ -e /etc/sysctl.d/51-alt-sysrq.conf ] && rm /etc/sysctl.d/51-alt-sysrq.conf
# switch to multi-users runlevel (instead of x11)
	ln -sf /lib/systemd/system/multi-user.target /etc/systemd/system/default.target
#	GRUB modifications (only one time)
# limit wait time to 3s
# create an alcasar entry instead of linux-nonfb
# change display to 1024*768 (vga791)
	grub_already_modified=`grep ALCASAR /boot/grub/menu.lst|wc -l`
	if [ $grub_already_modified == 0 ]
		then
		$SED "s?^timeout.*?timeout 3?g" /boot/grub/menu.lst
		$SED "s?^title linux?title ALCASAR?g" /boot/grub/menu.lst
		$SED "/^kernel/s/splash quiet //" /boot/grub/menu.lst
		$SED "/^kernel/s/$/ vga=791/" /boot/grub/menu.lst
		$SED "/^kernel/s/BOOT_IMAGE=linux /BOOT_IMAGE=linux-nonfb /" /boot/grub/menu.lst
		$SED "/^gfxmenu/d" /boot/grub/menu.lst
	fi
# Remove unused services and users
	for svc in sshd
	do
		/usr/bin/systemctl -q enable $svc.service
	done
# Load and apply the previous conf file
	if [ "$mode" = "update" ]
	then
		$DIR_DEST_BIN/alcasar-archive.sh --now # exports current logs in /var/Save/archive
		$DIR_DEST_BIN/alcasar-conf.sh --load
		PARENT_SCRIPT=`basename $0`
		export PARENT_SCRIPT # to avoid stop&start process during the installation process
		$DIR_DEST_BIN/alcasar-conf.sh --apply
		$SED "s?^INSTALL_DATE=.*?INSTALL_DATE=$DATE?g" $CONF_FILE
		$SED "s?^VERSION=.*?VERSION=$VERSION?g" $CONF_FILE
	fi
	rm -f /tmp/alcasar-conf*
	chown -R root:apache $DIR_DEST_ETC/*
	chmod -R 660 $DIR_DEST_ETC/*
	chmod ug+x $DIR_DEST_ETC/digest
	cd $DIR_INSTALL
	echo ""
	echo "#############################################################################"
	if [ $Lang == "fr" ]
		then
		echo "#                        Fin d'installation d'ALCASAR                       #"
		echo "#                                                                           #"
		echo "#         Application Libre pour le Contrôle Authentifié et Sécurisé        #"
		echo "#                     des Accès au Réseau ( ALCASAR )                       #"
		echo "#                                                                           #"
		echo "#############################################################################"
		echo
		echo "- ALCASAR sera fonctionnel après redémarrage du système"
		echo
		echo "- Lisez attentivement la documentation d'exploitation"
		echo
		echo "- Le centre de controle d'ALCASAR (ACC) est à l'adresse http://alcasar"
		echo
		echo "                   Appuyez sur 'Entrée' pour continuer"
	else	
		echo "#                        Enf of ALCASAR install process                     #"
		echo "#                                                                           #"
		echo "#         Application Libre pour le Contrôle Authentifié et Sécurisé        #"
		echo "#                     des Accès au Réseau ( ALCASAR )                       #"
		echo "#                                                                           #"
		echo "#############################################################################"
		echo
		echo "- The system will be rebooted in order to operate ALCASAR"
		echo
		echo "- Read the exploitation documentation"
		echo
		echo "- The ALCASAR Control Center (ACC) is at http://alcasar"
		echo
		echo "                   Hit 'Enter' to continue"
	fi
	sleep 2
	if [ "$mode" != "update" ]
	then
		read a
	fi
	clear
	reboot
} # End post_install ()

#################################
#  	Main Install loop  	#
#################################
dir_exec=`dirname "$0"`
if [ $dir_exec != "." ]
then
	echo "Lancez ce programme depuis le répertoire de l'archive d'ALCASAR"
	echo "Launch this program from the ALCASAR archive directory"
	exit 0
fi
VERSION=`cat $DIR_INSTALL/VERSION`
usage="Usage: alcasar.sh {-i or --install} | {-u or --uninstall}"
nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	nb_args=1
	args="-h"
fi
chmod -R u+x $DIR_SCRIPTS/*
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	-i | --install)
		header_install
		license
		header_install
		testing
# RPMs install
		$DIR_SCRIPTS/alcasar-urpmi.sh
		if [ "$?" != "0" ]
		then
			exit 0
		fi
		if [ -e $CONF_FILE ]
		then
# Uninstall the running version
			$DIR_SCRIPTS/sbin/alcasar-uninstall.sh
		fi
# Test if manual update	
		if [ -e /tmp/alcasar-conf*.tar.gz ] && [ "$mode" == "install" ]
		then
			header_install
			if [ $Lang == "fr" ]
				then echo "Le fichier de configuration d'une ancienne version a été trouvé";
				else echo "The configuration file of an old version has been found";
			fi
			response=0
			PTN='^[oOnNyY]$'
			until [[ $(expr $response : $PTN) -gt 0 ]]
			do
				if [ $Lang == "fr" ]
					then echo -n "Voulez-vous l'utiliser (O/n)? ";
					else echo -n "Do you want to use it (Y/n)?";
				 fi
				read response
				if [ "$response" = "n" ] || [ "$response" = "N" ] 
				then rm -f /tmp/alcasar-conf*
				fi
			done
		fi
# Test if update
		if [ -e /tmp/alcasar-conf* ] 
		then
			if [ $Lang == "fr" ]
				then echo "#### Installation avec mise à jour ####";
				else echo "#### Installation with update     ####";
			fi
# Extract the central configuration file
			tar -xf /tmp/alcasar-conf* conf/etc/alcasar.conf 
			ORGANISME=`grep ORGANISM conf/etc/alcasar.conf|cut -d"=" -f2`
			PREVIOUS_VERSION=`grep VERSION conf/etc/alcasar.conf|cut -d"=" -f2`
			MAJ_PREVIOUS_VERSION=`echo $PREVIOUS_VERSION|cut -d"." -f1`
			MIN_PREVIOUS_VERSION=`echo $PREVIOUS_VERSION|cut -d"." -f2|cut -c1`
			UPD_PREVIOUS_VERSION=`echo $PREVIOUS_VERSION|cut -d"." -f3`
			mode="update"
		fi
		for func in init network ACC CA init_db radius radius_web chilli dansguardian antivirus tinyproxy ulogd nfsen vnstat dnsmasq BL cron fail2ban gammu_smsd post_install
		do
			$func
# echo "*** 'debug' : end of function $func ***"; read a
		done
		;;
	-u | --uninstall)
		if [ ! -e $DIR_DEST_SBIN/alcasar-uninstall.sh ]
		then
			if [ $Lang == "fr" ]
				then echo "ALCASAR n'est pas installé!";
				else echo "ALCASAR isn't installed!";
			fi
			exit 0
		fi
		response=0
		PTN='^[oOnN]$'
		until [[ $(expr $response : $PTN) -gt 0 ]]
		do
			if [ $Lang == "fr" ]
				then echo -n "Voulez-vous créer le fichier de configuration de la version actuelle (0/n)? ";
				else echo -n "Do you want to create the running version configuration file (Y/n)? ";
			fi
			read response
		done
		if [ "$response" = "o" ] || [ "$response" = "O" ] || [ "$response" = "Y" ] || [ "$response" = "y" ]
		then
			$DIR_SCRIPTS/alcasar-conf.sh --create
		else	
			rm -f /tmp/alcasar-conf*
		fi
# Uninstall the running version
		$DIR_SCRIPTS/sbin/alcasar-uninstall.sh
		;;
	*)
		echo "Argument inconnu :$1";
		echo "Unknown argument :$1";
		echo "$usage"
		exit 1
		;;
esac
# end of script

