#!/bin/bash
# $Id: alcasar-iptables-bypass.sh 1551 2015-01-10 16:00:48Z richard $

# alcasar-iptables-bypass.sh
# by Rexy - 3abtux
# This script is distributed under the Gnu General Public License (GPL)

# applique les regles du parefeu en mode ByPass
# put the firewall rules in 'ByPass' mode

CONF_FILE="/usr/local/etc/alcasar.conf"
private_ip_mask=`grep PRIVATE_IP= $CONF_FILE|cut -d"=" -f2`
private_ip_mask=${private_ip_mask:=192.168.182.1/24}
private_network=`/bin/ipcalc -n $private_ip_mask|cut -d"=" -f2`		# LAN IP address (ie.: 192.168.182.0)
private_prefix=`/bin/ipcalc -p $private_ip_mask|cut -d"=" -f2`		# LAN prefix (ie. 24)
IPTABLES="/sbin/iptables"
EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`				# EXTernal InterFace
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`				# INTernal InterFace
PRIVATE_NETWORK_MASK=$private_network/$private_prefix			# Lan IP address + prefix (192.168.182.0/24)
PRIVATE_IP=`echo $private_ip_mask | cut -d"/" -f1`			# ALCASAR LAN IP address
public_ip_mask=`grep PUBLIC_IP= $CONF_FILE|cut -d"=" -f2`		# ALCASAR WAN IP address
PUBLIC_IP=`echo $public_ip_mask | cut -d"/" -f1`
SSH=`grep SSH= $CONF_FILE|cut -d"=" -f2`				# sshd active (on/off)
SSH=${SSH:=off}
SSH_ADMIN_FROM=`grep SSH_ADMIN_FROM= $CONF_FILE|cut -d"=" -f2`
SSH_ADMIN_FROM=${SSH_ADMIN_FROM:="0.0.0.0/0.0.0.0"}				# WAN IP address to reduce ssh access (all ip allowed on LAN side)


# On vide (flush) toutes les règles existantes
# Flush all existing rules
$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -F INPUT
$IPTABLES -F FORWARD
$IPTABLES -F OUTPUT

# On indique les politiques par défaut
# Default policies
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -t nat -P PREROUTING ACCEPT
$IPTABLES -t nat -P POSTROUTING ACCEPT
$IPTABLES -t nat -P OUTPUT ACCEPT

# On efface toutes les chaînes qui ne sont pas par défaut dans les tables filter et nat
# Flush non default rules on filter and nat tables
$IPTABLES -X
$IPTABLES -t nat -X

# On autorise tout sur loopback
# accept all on loopback
$IPTABLES -A OUTPUT -o lo -j ACCEPT
$IPTABLES -A INPUT -i lo -j ACCEPT

# Insertion de règles de blocage (Devel)
# Here, we add block rules (Devel)
if [ -s /usr/local/etc/alcasar-iptables-block ]; then 
	while read ip_line
	do
		ip_on=`echo $ip_line|cut -b1`
		if [ $ip_on != "#" ]
		then	
			ip_blocked=`echo $ip_line|cut -d" " -f1`
			$IPTABLES -A FORWARD -d $ip_blocked -j ULOG --ulog-prefix "RULE IP-blocked -- REJECT "
			$IPTABLES -A FORWARD -d $ip_blocked -j REJECT
		fi
	done < /usr/local/etc/alcasar-iptables-block
fi

# SSHD rules if activate 
if [ $SSH = on ]
	then
	$IPTABLES -A INPUT -i $INTIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport ssh -m state --state NEW -j ULOG --ulog-nlgroup 2 --ulog-prefix "RULE ssh-from-LAN -- ACCEPT"
	$IPTABLES -A INPUT -i $INTIF -s $PRIVATE_NETWORK_MASK -d $PRIVATE_IP -p tcp --dport ssh -m state --state NEW -j ACCEPT
	$IPTABLES -A INPUT -i $EXTIF -s $SSH_ADMIN_FROM -d $PUBLIC_IP -p tcp --dport ssh -m state --state NEW --syn -j ULOG --ulog-nlgroup 2 --ulog-prefix "RULE ssh-from-WAN -- ACCEPT"
	$IPTABLES -A INPUT -i $EXTIF -s $SSH_ADMIN_FROM -d $PUBLIC_IP -p tcp --dport ssh -m state --state NEW -j ACCEPT
fi

# Insertion de règles locales
# Here, we add local rules (i.e. VPN from Internet)
if [ -f /usr/local/etc/alcasar-iptables-local.sh ]; then
        . /usr/local/etc/alcasar-iptables-local.sh
fi

# on autorise les requêtes dhcp
# accept dhcp
$IPTABLES -A INPUT -i $INTIF -p udp -m udp --sport bootpc --dport bootps -j ACCEPT

# On drop le broadcast et le multicast sur les interfaces (sans Log)
# Drop broadcast & multicast
$IPTABLES -A INPUT -m addrtype --dst-type BROADCAST,MULTICAST -j DROP

# On laisse passer les ICMP echo-request et echo-reply en provenance du LAN
# Allow ping (icmp N°0 & 8) from LAN
$IPTABLES -A INPUT -i $INTIF -s $PRIVATE_NETWORK_MASK -p icmp --icmp-type 0 -j ACCEPT
$IPTABLES -A INPUT -i $INTIF -s $PRIVATE_NETWORK_MASK -p icmp --icmp-type 8 -j ACCEPT

#  On ajoute ici les règles spécifiques de filtrage réseau (accès exterieur ...)
if [ -f /usr/local/etc/alcasar-iptables-local.sh ]; then
        . /usr/local/etc/alcasar-iptables-local.sh
fi

# On autorise les retours de connexions légitimes par FORWARD
# Conntrack on forward
$IPTABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# On autorise les demandes de connexions sortantes
$IPTABLES -A FORWARD -i $INTIF -m state --state NEW -j ULOG --ulog-prefix "RULE Transfert -- ACCEPT "
$IPTABLES -A FORWARD -i $INTIF -m state --state NEW -j ACCEPT

# On autorise les flux entrant ntp et dns via INTIF
$IPTABLES -A INPUT -i $INTIF -d $PRIVATE_IP -p udp --dport domain -j ACCEPT
$IPTABLES -A INPUT -i $INTIF -d $PRIVATE_IP -p udp --dport ntp -j ACCEPT

# On autorise le retour des connexions entrante déjà acceptées
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# On interdit et on log le reste sur les 2 interfaces d'accès
$IPTABLES -A INPUT -i $INTIF -j ULOG --ulog-prefix "RULE rej-int -- REJECT "
$IPTABLES -A INPUT -i $EXTIF -j ULOG --ulog-prefix "RULE rej-ext -- REJECT "
$IPTABLES -A INPUT -p tcp -j REJECT --reject-with tcp-reset
$IPTABLES -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable

# On active le masquage d'adresse par translation (NAT)
$IPTABLES -A POSTROUTING -t nat -o $EXTIF -j MASQUERADE

# on ne sauvegarde pas les règles. En cas de reboot, on repasse ainsi automatiquement en mode normal (bypass -off)
# Fin du script des regles du parefeu
