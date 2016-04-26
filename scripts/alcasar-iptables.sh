#!/bin/bash
# $Id: alcasar-iptables.sh 1769 2016-01-17 20:39:23Z richard $
# Script de mise en place des regles du parefeu d'Alcasar (mode normal)
# This script writes the netfilter rules for ALCASAR
# Rexy - 3abtux - CPN
#
# Reminders
# There are four channels for log :
#	1 tracability of the consultation equipment with The 'Netflow' kernel module (iptables target = NETFLOW);
#	2 protection of ALCASAR with the Ulog group 1 (default group) 
#	3 SSH on ALCASAR with the Ulog group 2;
#	4 extern access attempts on ALCASAR with the Ulog group 3.
# The bootps/dhcp (67) port is always open on tun0/INTIF by coova 
CONF_FILE="/usr/local/etc/alcasar.conf"
EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`				# EXTernal InterFace
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`				# INTernal InterFace
TUNIF="tun0"								# listen device for chilli daemon
private_ip_mask=`grep ^PRIVATE_IP= $CONF_FILE|cut -d"=" -f2`
private_ip_mask=${private_ip_mask:=192.168.182.1/24}
PRIVATE_IP=`echo $private_ip_mask | cut -d"/" -f1`			# ALCASAR LAN IP address
private_network=`/bin/ipcalc -n $private_ip_mask|cut -d"=" -f2`		# LAN IP address (ie.: 192.168.182.0)
private_prefix=`/bin/ipcalc -p $private_ip_mask|cut -d"=" -f2`		# LAN prefix (ie. 24)
PRIVATE_NETWORK_MASK=$private_network/$private_prefix			# Lan IP address + prefix (192.168.182.0/24)
public_ip_mask=`grep ^PUBLIC_IP= $CONF_FILE|cut -d"=" -f2`		# ALCASAR WAN IP address
if [[ "$public_ip_mask" == "dhcp" ]]
then
	PTN="\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([012]?[0-9]|3[0-2])\b"
	public_ip_mask=`ip addr show $EXTIF | egrep -o $PTN`
fi
PUBLIC_IP=`echo $public_ip_mask | cut -d"/" -f1`
dns1=`grep ^DNS1= $CONF_FILE|cut -d"=" -f2`
dns2=`grep ^DNS2= $CONF_FILE|cut -d"=" -f2`
dns1=${dns1:=208.67.220.220}
dns2=${dns2:=208.67.222.222}
DNSSERVERS="$dns1,$dns2"						# first and second public DNS servers
PROTOCOLS_FILTERING=`grep ^PROTOCOLS_FILTERING= $CONF_FILE|cut -d"=" -f2`	# Network protocols filter (on/off)
PROTOCOLS_FILTERING=${PROTOCOLS_FILTERING:=off}
BL_IP_CAT="/usr/local/share/iptables-bl-enabled"			# categories files of the BlackListed IP
BL_IP_OSSI="/usr/local/share/iptables-bl/ossi"				# ossi categoty
WL_IP_OSSI="/usr/local/share/ossi-ip-wl"				# ip of the whitelist
DNSMASQ_WL_ENABLED="/usr/local/share/dnsmasq-wl-enabled"		# enabled domain names for the Whitelist
TMP_users_set_save="/tmp/users_set_save"				# tmp file for backup users set 
TMP_set_save="/tmp/ipset_save"						# tmp file for blacklist and whitelist creation
SSH=`grep ^SSH= $CONF_FILE|cut -d"=" -f2`				# sshd active (on/off)
SSH=${SSH:=off}
SSH_ADMIN_FROM=`grep ^SSH_ADMIN_FROM= $CONF_FILE|cut -d"=" -f2`
SSH_ADMIN_FROM=${SSH_ADMIN_FROM:="0.0.0.0/0.0.0.0"}			# WAN IP address to reduce ssh access (all ip allowed on LAN side)
LDAP=`grep ^LDAP= $CONF_FILE|cut -d"=" -f2`				# LDAP external server active (on/off)
LDAP=${LDAP:=off}
LDAP_IP=`grep ^LDAP_IP= $CONF_FILE|cut -d"=" -f2`			# WAN IP address to reduce LDAP WAN access (all ip allowed on LAN side)
LDAP_IP=${LDAP_IP:="0.0.0.0/0.0.0.0"}
IPTABLES="/sbin/iptables"
IP_REHABILITEES="/etc/dansguardian/lists/exceptioniplist"		# Rehabilitated IP
SAVE_DIR="/etc/sysconfig"						# Saving path

# Sauvegarde des SET des utilisateurs connectés si ils existent
# Saving SET of connected users if it exists
ipset list no_filtering_set 1>/dev/null 2>&1
if [ $? -eq 0 ];
then
	ipset save no_filtering_set > $TMP_users_set_save
	ipset save havp_set >> $TMP_users_set_save
	ipset save havp_bl_set >> $TMP_users_set_save
	ipset save havp_wl_set >> $TMP_users_set_save
fi

# loading of NetFlow probe (ipt_NETFLOW kernel module)
modprobe ipt_NETFLOW destination=127.0.0.1:2055

# Effacement des règles existantes
# Flush all existing rules
$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -t mangle -F
$IPTABLES -F INPUT
$IPTABLES -F FORWARD
$IPTABLES -F OUTPUT

# Suppression des chaines utilisateurs sur les tables filter et nat
# Flush non default rules on filter and nat tables
$IPTABLES -X
$IPTABLES -t nat -X

# Stratégies par défaut
# Default policies
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -t nat -P PREROUTING ACCEPT
$IPTABLES -t nat -P POSTROUTING ACCEPT
$IPTABLES -t nat -P OUTPUT ACCEPT


#############################
#          IPSET            #
#############################

# destruction de tous les SET
# destroy all SET
ipset destroy

###### BL set  ###########
# Calcul de la taille / Compute the length
bl_set_length=$(($(wc -l $BL_IP_CAT/* | awk '{print $1}' | tail -n 1)+$(wc -l $BL_IP_OSSI | awk '{print $1}')))
# Chargement / loading
echo "create blacklist_ip_blocked hash:net family inet hashsize 1024 maxelem $bl_set_length" > $TMP_set_save
for category in `ls -1 $BL_IP_CAT | cut -d '@' -f1`
do
	cat $BL_IP_CAT/$category >> $TMP_set_save
done
cat $BL_IP_OSSI >> $TMP_set_save
ipset -! restore < $TMP_set_save
rm -f $TMP_set_save
# Suppression des ip réhabilitées / Removing of rehabilitated ip
for ip in $(cat $IP_REHABILITEES)
do
	ipset del blacklist_ip_blocked $ip
done

###### WL set  ###########
# Calcul de la taille / Compute the length
wl_set_length=$(($(wc -l $DNSMASQ_WL_ENABLED/* | awk '{print $1}' | tail -n 1)*3))
# Chargement Loading
echo "create whitelist_ip_allowed hash:net family inet hashsize 1024 maxelem $wl_set_length" > $TMP_set_save
cat $WL_IP_OSSI >> $TMP_set_save
ipset -! restore < $TMP_set_save
rm -f $TMP_set_save

# Restoration des SET des utilisateurs connectés si ils existent sinon création des SET 
# Restoring the connected users SETs if available, otherwise creating SETs
if [ -e $TMP_users_set_save ];
then
	ipset -! restore < $TMP_users_set_save
	rm -f $TMP_users_set_save
else
	ipset create no_filtering_set hash:net hashsize 1024
	ipset create havp_set hash:net hashsize 1024
	ipset create havp_bl_set hash:net hashsize 1024
	ipset create havp_wl_set hash:net hashsize 1024
fi

#############################
#       PREROUTING          #
#############################
# Marquage des paquets qui tentent d'accéder directement à un serveur sans authentification en mode proxy pour pouvoir les rejeter en INPUT
# Mark packets that attempt to directly access a server without authentication with proxy client to reject them in INPUT rules
#$IPTABLES -A PREROUTING -t mangle -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp -m tcp --dport 80 -m string --string 'GET http' --algo bm --from 50 --to 70 -j MARK --set-mark 10

# Marquage (et journalisation) des paquets qui tentent d'accéder directement au 8080 (DansGuardian) pour pouvoir les rejeter en INPUT
# mark (and log) the dansguardian bypass attempts in order to DROP them in INPUT rules
$IPTABLES -A PREROUTING -t nat -i $TUNIF -p tcp -d $PRIVATE_IP -m tcp --dport 8080 -j NFLOG --nflog-prefix "RULE direct-proxy -- DENY "
$IPTABLES -A PREROUTING -t mangle -i $TUNIF -d $PRIVATE_IP -p tcp -m tcp --dport 8080 -j MARK --set-mark 1

# Marquage (et journalisation) des paquets qui tentent d'accéder directement au port 8090 (tinyproxy) pour pouvoir les rejeter en INPUT
# Mark (and log) the 8090 direct attempts to REJECT them in INPUT rules
$IPTABLES -A PREROUTING -t nat -i $TUNIF -p tcp -d $PRIVATE_IP -m tcp --dport 8090 -j NFLOG --nflog-prefix "RULE direct-proxy -- DENY "
$IPTABLES -A PREROUTING -t mangle -i $TUNIF -d $PRIVATE_IP -p tcp -m tcp --dport 8090 -j MARK --set-mark 2

# Marquage des paquets qui tentent d'accéder directement au port udp 54 (DNS-blacklist) pour pouvoir les rejeter en INPUT
# Mark the udp 54 direct attempts (DNS-blacklist) to REJECT them in INPUT rules
$IPTABLES -A PREROUTING -t mangle -i $TUNIF -d $PRIVATE_IP -p tcp --dport 54 -j MARK --set-mark 3

# Marquage des paquets qui tentent d'accéder directement au port udp 55 (DNS-Whitelist) pour pouvoir les rejeter en INPUT
# Mark the udp 55 direct attempts (DNS-whitelist) to REJECT them in INPUT rules
$IPTABLES -A PREROUTING -t mangle -i $TUNIF -d $PRIVATE_IP -p tcp --dport 55 -j MARK --set-mark 4

# Marquage des paquets qui tentent d'accéder directement au port udp 56 (DNS-Blackhole) pour pouvoir les rejeter en INPUT
# Mark the udp 56 direct attempts (DNS-blackhole) to REJECT them in INPUT rules
$IPTABLES -A PREROUTING -t mangle -i $TUNIF -d $PRIVATE_IP -p tcp --dport 56 -j MARK --set-mark 5

# redirection DNS des usagers 'havp_bl' vers le port 54
# redirect DNS of 'havp_bl' users to port 54
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_bl_set src -d $PRIVATE_IP -p udp --dport domain -j REDIRECT --to-port 54

# redirection DNS des usagers 'havp_wl' vers le port 55
# redirect DNS of 'havp_bl' users to port 55
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_wl_set src -d $PRIVATE_IP -p udp --dport domain -j REDIRECT --to-port 55

# Journalisation HTTP_Internet des usagers 'havp_bl' (paquets SYN uniquement). Les autres protocoles sont journalisés en FORWARD par netflow. 
# Log Internet HTTP of 'havp_bl' users" (only syn packets). Other protocols are logged in FORWARD by netflow
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_bl_set src ! -d $PRIVATE_IP -p tcp --dport http -m state --state NEW -j NFLOG --nflog-prefix "RULE F_http -- ACCEPT "

# Redirection HTTP des usagers 'havp_bl' cherchant à joindre les IP de la blacklist vers ALCASAR (page 'accès interdit')
# Redirect HTTP of 'havp_bl' users who want blacklist IP to ALCASAR ('access denied' page)
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_bl_set src -m set --match-set blacklist_ip_blocked dst -p tcp --dport http -j REDIRECT --to-port 80

# Redirection HTTP des usagers 'havp_wl' cherchant à joindre les IP qui ne sont pas dans la WL vers ALCASAR (page 'accès interdit')
# Redirect HTTP of 'havp_wl' users who want IP not in the WL to ALCASAR ('access denied' page)
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_wl_set src -m set ! --match-set whitelist_ip_allowed dst -p tcp --dport http -j REDIRECT --to-port 80

# Redirection des requêtes HTTP sortantes des usagers 'havp_bl' vers DansGuardian
# Redirect outbound HTTP requests of "BL" users to DansGuardian (transparent proxy)
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_bl_set src ! -d $PRIVATE_IP -p tcp --dport http -j REDIRECT --to-port 8080

# Redirection des requêtes HTTP sortantes des usager 'havp_wl' et 'havp' vers Tinyproxy
# Redirect outbound HTTP requests for "WL-antivirus" users to Tinyproxy
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_wl_set src ! -d $PRIVATE_IP -p tcp --dport http -j REDIRECT --to-port 8090
$IPTABLES -A PREROUTING -t nat -i $TUNIF -m set --match-set havp_set src ! -d $PRIVATE_IP -p tcp --dport http -j REDIRECT --to-port 8090

# Redirection des requêtes NTP vers le serveur NTP local
# Redirect NTP request in local NTP server
$IPTABLES -A PREROUTING -t nat -i $TUNIF -s $PRIVATE_NETWORK_MASK ! -d $PRIVATE_IP -p udp --dport ntp -j REDIRECT --to-port 123

#############################
#         INPUT             #
#############################

# Tout passe sur loopback
# accept all on loopback
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Rejet des demandes de connexions non conformes (FIN-URG-PUSH, XMAS, NullScan, SYN-RST et NEW not SYN)
# Drop non standard connexions (FIN-URG-PUSH, XMAS, NullScan, SYN-RST et NEW not SYN)
$IPTABLES -A INPUT -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A INPUT -p tcp -m tcp ! --syn -m state --state NEW -j DROP

# Si configéré, on autorise les réponses DHCP 
# Allow DHCP answers if configured
public_ip_mask=`grep ^PUBLIC_IP= $CONF_FILE|cut -d"=" -f2`		# ALCASAR WAN IP address
if [[ "$public_ip_mask" == "dhcp" ]]
then
	$IPTABLES -A OUTPUT -o $EXTIF -p tcp --dport 68 -j ACCEPT
	$IPTABLES -A OUTPUT -o $EXTIF -p udp --dport 68 -j ACCEPT
fi
# On rejette les trame en broadcast et en multicast sur EXTIF (évite leur journalisation)
# Drop broadcast & multicast on EXTIF to avoid log 
$IPTABLES -A INPUT -m addrtype --dst-type BROADCAST,MULTICAST -j DROP

# On autorise les retours de connexions légitimes par INPUT
# Conntrack on INPUT
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# On interdit les connexions directes au port utilisé par DansGuardian (8080). Les packets concernés ont été marqués et loggués dans la table mangle (PREROUTING)
# Deny direct connections on DansGuardian port (8080). The concerned paquets have been marked and logged in mangle table (PREROUTING)
$IPTABLES -A INPUT -i $TUNIF -p tcp --dport 8080 -m mark --mark 1 -j REJECT --reject-with tcp-reset

# Autorisation des connexions légitimes à DansGuardian 
# Allow connections for DansGuardian
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport 8080 -m state --state NEW --syn -j ACCEPT

# On interdit les connexions directes au port utilisé par tinyproxy (8090). Les packets concernés ont été marqués et loggués dans la table mangle (PREROUTING)
# Deny direct connections on tinyproxy port (8090). The concerned paquets have been marked in mangle table (PREROUTING)
$IPTABLES -A INPUT -i $TUNIF -p tcp --dport 8090 -m mark --mark 2 -j REJECT --reject-with tcp-reset

# Autorisation des connexions légitimes vers tinyproxy 
# Allow connections to tinyproxy
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport 8090 -m state --state NEW --syn -j ACCEPT

# On interdit les connexions directes au port UDP 54 (DNS-blacklist). Les packets concernés ont été marqués dans la table mangle (PREROUTING)
# Deny direct connections on UDP 54 (DNS-blacklist). The concerned paquets are marked in mangle table (PREROUTING)
$IPTABLES -A INPUT -i $TUNIF -p tcp --dport 54 -m mark --mark 3 -j REJECT --reject-with icmp-port-unreachable

# On interdit les connexions directes au port UDP 55 (DNS-whitelist). Les packets concernés ont été marqués dans la table mangle (PREROUTING)
# Deny direct connections on UDP 55 (DNS-whitelist). The concerned paquets are marked in mangle table (PREROUTING)
$IPTABLES -A INPUT -i $TUNIF -p tcp --dport 55 -m mark --mark 4 -j REJECT --reject-with icmp-port-unreachable

# On interdit les connexions directes au port UDP 56 (DNS-Blackhole). Les packets concernés ont été marqués dans la table mangle (PREROUTING)
# Deny direct connections on UDP 56 (DNS-blackhole). The concerned paquets are marked in mangle table (PREROUTING)
$IPTABLES -A INPUT -i $TUNIF -p tcp --dport 56 -m mark --mark 5 -j REJECT --reject-with icmp-port-unreachable

# autorisation des connexion légitime à DNSMASQ (avec blacklist)
# Allow connections for DNSMASQ (with blacklist)
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p udp --dport 54 -j ACCEPT

# autorisation des connexion légitime à DNSMASQ (avec whitelist)
# Allow connections for DNSMASQ (with whitelist)
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p udp --dport 55 -j ACCEPT

# autorisation des connexion légitime à DNSMASQ (mode blackhole)
# Allow connections for DNSMASQ (blackhole mode)
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p udp --dport 56 -j ACCEPT

# Accès direct aux services internes
# Internal services access
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p udp --dport domain -j ACCEPT	# DNS non filtré # DNS without blacklist
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p icmp --icmp-type 8 -j ACCEPT	# Réponse ping # ping responce
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p icmp --icmp-type 0 -j ACCEPT	# Requête  ping # ping request
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport https -j ACCEPT	# Pages d'authentification et MCC # authentication pages and MCC
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport http -j ACCEPT	# Page d'avertissement filtrage # Filtering warning pages
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport 3990 -j ACCEPT	# Requêtes de deconnexion usagers # Users logout requests
$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p udp --dport ntp -j ACCEPT	# Serveur local de temps # local time server

# SSHD rules if activate 
if [ $SSH = on ]
	then
	$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport ssh -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "RULE ssh-from-LAN -- ACCEPT"
	$IPTABLES -A INPUT -i $TUNIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport ssh -j ACCEPT
	$IPTABLES -A INPUT -i $EXTIF -s $SSH_ADMIN_FROM -d $PUBLIC_IP -p tcp --dport ssh -m state --state NEW --syn -j NFLOG --nflog-group 2 --nflog-prefix "RULE ssh-from-WAN -- ACCEPT"
	$IPTABLES -A INPUT -i $EXTIF -s $SSH_ADMIN_FROM -d $PUBLIC_IP -p tcp --dport ssh -m state --state NEW -j ACCEPT
fi

# Insertion de règles locales
# Here, we add local rules (i.e. VPN from Internet)
if [ -f /usr/local/etc/alcasar-iptables-local.sh ]; then
        . /usr/local/etc/alcasar-iptables-local.sh
fi

# Journalisation et rejet des connexions (autres que celles autorisées) effectuées depuis le LAN
# Deny and log on INPUT from the LAN
$IPTABLES -A INPUT -i $TUNIF -m state --state NEW -j NFLOG --nflog-prefix "RULE rej-int -- REJECT "
$IPTABLES -A INPUT -i $TUNIF -p tcp -j REJECT --reject-with tcp-reset
$IPTABLES -A INPUT -i $TUNIF -p udp -j REJECT --reject-with icmp-port-unreachable

# Interdiction d'accès à INTIF (n'est utile que lorsque chilli est arrêté).
# Reject INTIF access (only when chilli is down)
$IPTABLES -A INPUT -i $INTIF -j NFLOG --nflog-prefix "RULE Protect1 -- REJECT "
$IPTABLES -A INPUT -i $INTIF -j REJECT

# Journalisation et rejet des connexions initiées depuis le réseau extérieur (test des effets du paramètre --limit en cours)
# On EXTIF, the access attempts are log in channel 2 (we should test --limit option to avoid deny of service)
$IPTABLES -A INPUT -i $EXTIF -m state --state NEW -j NFLOG --nflog-group 3 --nflog-threshold 10 --nflog-prefix "RULE rej-ext -- DROP"

#############################
#        FORWARD            #
#############################

# Blocage des IPs du SET blacklist_ip_blocked pour le SET havp_bl_set
# Deny IPs of the SET blacklist_ip_blocked for the set havp_bl_set
$IPTABLES -A FORWARD -i $TUNIF -m set --match-set havp_bl_set src -m set --match-set blacklist_ip_blocked dst -p icmp -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A FORWARD -i $TUNIF -m set --match-set havp_bl_set src -m set --match-set blacklist_ip_blocked dst -p udp -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A FORWARD -i $TUNIF -m set --match-set havp_bl_set src -m set --match-set blacklist_ip_blocked dst -p tcp -j REJECT --reject-with tcp-reset

# Rejet des requêtes DNS vers Internet
# Deny forward DNS
$IPTABLES -A FORWARD -i $TUNIF -p udp --dport domain -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A FORWARD -i $TUNIF -p tcp --dport domain -j REJECT --reject-with tcp-reset

# Autorisation des retours de connexions légitimes
$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

#  If protocols filter is activate
if [ $PROTOCOLS_FILTERING = on ]; then
	# Compute uamallowed IP (IP address of equipments connected between ALCASAR and Internet (DMZ, own servers, ...) 
	nb_uamallowed=`wc -l /usr/local/etc/alcasar-uamallowed | cut -d" "  -f1`
	if [ $nb_uamallowed != "0" ]
	then
		while read ip_allowed_line 
		do
			ip_allowed=`echo $ip_allowed_line|cut -d"\"" -f2`
			$IPTABLES -A FORWARD -i $TUNIF -d $ip_allowed -m state --state NEW -j NFLOG --nflog-prefix "RULE IP-allowed -- ACCEPT "
			$IPTABLES -A FORWARD -i $TUNIF -d $ip_allowed -m state --state NEW -j NETFLOW
			$IPTABLES -A FORWARD -i $TUNIF -d $ip_allowed -m state --state NEW -j ACCEPT
		done < /usr/local/etc/alcasar-uamallowed
	fi
	# Autorisation du HTTP et des protocoles non commentés
	# Allow HTTP and non comment protocols
	$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport http -m state --state NEW -j NFLOG --nflog-prefix "RULE F_TCP-$svc_name -- ACCEPT "
	$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport http -m state --state NEW -j NETFLOW
	$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport http -m state --state NEW -j ACCEPT
	while read svc_line
	do
		svc_on=`echo $svc_line|cut -b1`
		if [ $svc_on != "#" ]
		then	
			svc_name=`echo $svc_line|cut -d" " -f1`
			svc_port=`echo $svc_line|cut -d" " -f2`
			if [ $svc_name = "icmp" ]
			then
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p icmp -j NETFLOW
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p icmp -j ACCEPT 
			else

				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport $svc_port -m state --state NEW -j NFLOG --nflog-prefix "RULE F_TCP-$svc_name -- ACCEPT "
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport $svc_port -m state --state NEW -j NETFLOW
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p tcp --dport $svc_port -m state --state NEW -j ACCEPT
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p udp --dport $svc_port -m state --state NEW -j NFLOG --nflog-prefix "RULE F_UDP-$svc_name -- ACCEPT "
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p udp --dport $svc_port -m state --state NEW -j NETFLOW
				$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -p udp --dport $svc_port -m state --state NEW -j ACCEPT
			fi
		fi
	done < /usr/local/etc/alcasar-services
	# Rejet explicite des autres protocoles
	# reject the others protocols
	$IPTABLES -A FORWARD -i $TUNIF -j NFLOG --nflog-prefix "RULE F_filter -- REJECT "
	$IPTABLES -A FORWARD -i $TUNIF -p tcp -j REJECT --reject-with tcp-reset
	$IPTABLES -A FORWARD -i $TUNIF -p udp -j REJECT --reject-with icmp-port-unreachable
	$IPTABLES -A FORWARD -i $TUNIF -p icmp -j REJECT 
fi

# Autorisation des connections sortant du LAN  
# Allow forward connections with log
#$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -m state --state NEW -j ULOG --ulog-prefix "RULE F_all -- ACCEPT "
$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -m state --state NEW -j NETFLOW
$IPTABLES -A FORWARD -i $TUNIF -s $PRIVATE_NETWORK_MASK -m state --state NEW -j ACCEPT

#############################
#         OUTPUT            #
#############################
# On laisse tout sortir sur toutes les cartes sauf celle qui est connectée sur l'extérieur
# Everything is allowed but traffic through outside network interface
$IPTABLES -A OUTPUT ! -o $EXTIF -j ACCEPT

# Si configéré, on autorise les requêtes DHCP 
# Allow DHCP requests if configured
public_ip_mask=`grep ^PUBLIC_IP= $CONF_FILE|cut -d"=" -f2`		# ALCASAR WAN IP address
if [[ "$public_ip_mask" == "dhcp" ]]
then
	$IPTABLES -A OUTPUT -o $EXTIF -p tcp --dport 67 -j ACCEPT
	$IPTABLES -A OUTPUT -o $EXTIF -p udp --dport 67 -j ACCEPT
fi

# On autorise les requêtes DNS vers les serveurs DNS identifiés 
# Allow DNS requests to identified DNS servers
$IPTABLES -A OUTPUT -o $EXTIF -d $DNSSERVERS -p udp --dport domain -m state --state NEW -j ACCEPT

# On autorise les requêtes HTTP sortantes
# HTTP requests are allowed
$IPTABLES -A OUTPUT -o $EXTIF -p tcp --dport http -j NETFLOW
$IPTABLES -A OUTPUT -o $EXTIF -p tcp --dport http -j ACCEPT

# On autorise les requêtes FTP 
# FTP requests are allowed
modprobe nf_conntrack_ftp
$IPTABLES -A OUTPUT -o $EXTIF -p tcp --dport ftp -j ACCEPT
$IPTABLES -A OUTPUT -o $EXTIF -m state --state ESTABLISHED,RELATED -j ACCEPT

# On autorise les requêtes NTP 
# NTP requests are allowed
$IPTABLES -A OUTPUT -o $EXTIF -p udp --dport ntp -j ACCEPT

# On autorise les requêtes ICMP (ping) 
# ICMP (ping) requests are allowed
$IPTABLES -A OUTPUT -o $EXTIF -p icmp --icmp-type 8 -j ACCEPT

# On autorise les requêtes LDAP si un serveur externe est configué
# LDAP requests are allowed if an external server is declared
if [ $LDAP = on ]
	then
	$IPTABLES -A OUTPUT -p tcp -d $LDAP_IP -m multiport --dports ldap,ldaps -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPTABLES -A OUTPUT -p udp -d $LDAP_IP -m multiport --dports ldap,ldaps -m state --state NEW,ESTABLISHED -j ACCEPT
fi

#############################
#       POSTROUTING         #
#############################
# Traduction dynamique d'adresse en sortie
# Dynamic NAT on EXTIF
$IPTABLES -A POSTROUTING -t nat -o $EXTIF -j MASQUERADE

# End of script

