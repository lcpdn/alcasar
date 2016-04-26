#/bin/bash
# $Id: alcasar-dhcp.sh 1783 2016-01-21 17:24:43Z franck $

# alcasar-dhcp.sh

# by Rexy
# This script is distributed under the Gnu General Public License (GPL)

# active ou desactive le service DHCP sur le réseau de consultation
# enable or disable the DHCP service on consultation LAN

SED="/bin/sed -i"
CHILLI_CONF_FILE="/etc/chilli.conf"
ALCASAR_CONF_FILE="/usr/local/etc/alcasar.conf"
DNSMASQ_CONF_FILE="/etc/dnsmasq.conf"

# define DHCP parameters (LAN side)
PRIVATE_IP_MASK=`grep PRIVATE_IP $ALCASAR_CONF_FILE|cut -d"=" -f2`
PRIVATE_IP=`echo $PRIVATE_IP_MASK | cut -d"/" -f1`
PRIVATE_PREFIX=`/bin/ipcalc -p $PRIVATE_IP_MASK |cut -d"=" -f2`				# network prefix (ie. 24)
PRIVATE_NETMASK=`/bin/ipcalc -m $PRIVATE_IP_MASK | cut -d"=" -f2`
PRIVATE_NETWORK=`/bin/ipcalc -n $PRIVATE_IP $PRIVATE_NETMASK| cut -d"=" -f2`
PRIVATE_PREFIX=`/bin/ipcalc -p $PRIVATE_IP $PRIVATE_NETMASK |cut -d"=" -f2`
PRIVATE_NETWORK_MASK=$PRIVATE_NETWORK/$PRIVATE_PREFIX					# ie.: 192.168.182.0/24
classe=$((PRIVATE_PREFIX/8)); classe_sup=`expr $classe + 1`; classe_sup_sup=`expr $classe + 2`		# ie.: 2=classe B, 3=classe C
PRIVATE_BROADCAST=`/bin/ipcalc -b $PRIVATE_NETWORK_MASK | cut -d"=" -f2`		# private network broadcast (ie.: 192.168.182.255)
private_network_ending=`echo $PRIVATE_NETWORK | cut -d"." -f$classe_sup`		# last octet of LAN address
private_broadcast_ending=`echo $PRIVATE_BROADCAST | cut -d"." -f$classe_sup`		# last octet of LAN broadcast
PRIVATE_FIRST_IP=`echo $PRIVATE_NETWORK | cut -d"." -f1-3`"."`expr $private_network_ending + 1`		# First network address (ex.: 192.168.182.1)
PRIVATE_LAST_IP=`echo $PRIVATE_BROADCAST | cut -d"." -f1-3`"."`expr $private_broadcast_ending - 1`	# last network address (ex.: 192.168.182.254)
PRIVATE_NETWORK_MASK=$PRIVATE_NETWORK/$PRIVATE_PREFIX
EXT_DHCP_IP=`grep EXT_DHCP_IP $ALCASAR_CONF_FILE|cut -d"=" -f2`				# Adresse du serveur DHCP externe
RELAY_DHCP_IP=`grep RELAY_DHCP_IP $ALCASAR_CONF_FILE|cut -d"=" -f2`			# Adresse de l'agent Relay : IP interne (défaut 192.168.182.1) dans le cas de DHCP dans le LAN de consultation
RELAY_DHCP_IP=${RELAY_DHCP_IP:=$PRIVATE_IP}						# IP externe (défaut x.y.z.t) dans le cas de DHCP du côté WAN
RELAY_DHCP_PORT=`grep RELAY_DHCP_PORT $ALCASAR_CONF_FILE|cut -d"=" -f2`			# Port de redirection vers le relay DHCP :  67 par défaut
RELAY_DHCP_PORT=${RELAY_DHCP_PORT:=67}

usage="Usage: alcasar-dhcp.sh {--on | -on} | {--off | -off}"
nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	echo "$usage"
	exit 1
fi
case $args in
	-\? | -h | --h)
		echo "$usage"
		exit 0
		;;
	--off|-off) # disable DHCP service
		$SED "s?.*statip.*?statip\t\t$PRIVATE_NETWORK_MASK?g" $CHILLI_CONF_FILE
		$SED "s?^#nodynip.*?nodynip?g" $CHILLI_CONF_FILE
		$SED "s?^dynip.*?#dynip?g" $CHILLI_CONF_FILE
		$SED "s?^#dynip.*?#dynip?g" $CHILLI_CONF_FILE
		$SED "s?^DHCP.*?DHCP=off?g" $ALCASAR_CONF_FILE
		if [ "$EXT_DHCP_IP" != "none" ] 
		then
		      $SED "s?.*dhcpgateway\t.*?dhcpgateway\t\t $EXT_DHCP_IP?g" $CHILLI_CONF_FILE
		      $SED "s?.*dhcprelayagent.*?dhcprelayagent\t\t$RELAY_DHCP_IP?g" $CHILLI_CONF_FILE
		      $SED "s?.*dhcpgatewayport.*?dhcpgatewayport\t\t$RELAY_DHCP_PORT?g" $CHILLI_CONF_FILE
		else
		      $SED "s?.*dhcpgateway\t.*?#dhcpgateway\t\t$EXT_DHCP_IP?g" $CHILLI_CONF_FILE
		      $SED "s?.*dhcprelayagent.*?#dhcprelayagent\t\t$RELAY_DHCP_IP?g" $CHILLI_CONF_FILE
		      $SED "s?.*dhcpgatewayport.*?#dhcpgatewayport\t\t$RELAY_DHCP_PORT?g" $CHILLI_CONF_FILE
		fi
		/usr/bin/systemctl restart chilli
		;;
	--on|-on) # enable DHCP service on all range of IP addresses
		$SED "s?^.*statip.*?#statip?g" $CHILLI_CONF_FILE
		$SED "s?^nodynip.*?#nodynip?g" $CHILLI_CONF_FILE
		$SED "s?^DHCP.*?DHCP=on?g" $ALCASAR_CONF_FILE
		$SED "s?^dynip.*?dynip\t\t$PRIVATE_NETWORK_MASK?g" $CHILLI_CONF_FILE
		$SED "s?^#dynip.*?dynip\t\t$PRIVATE_NETWORK_MASK?g" $CHILLI_CONF_FILE
		$SED "s?^dhcp_range.*?dhcp-range=$PRIVATE_FIRST_IP,$PRIVATE_LAST_IP,$PRIVATE_NETMASK,12h?g" $DNSMASQ_CONF_FILE
		$SED "s?^dhcpgateway\t.*?#dhcpgateway\t\t $EXT_DHCP_IP?g" $CHILLI_CONF_FILE
		$SED "s?^dhcprelayagent.*?#dhcprelayagent\t\t$RELAY_DHCP_IP?g" $CHILLI_CONF_FILE
		$SED "s?^dhcpgatewayport.*?#dhcpgatewayport\t\t$RELAY_DHCP_PORT?g" $CHILLI_CONF_FILE
		$SED "s?^EXT_DHCP_IP.*?EXT_DHCP_IP=$EXT_DHCP_IP?g" $ALCASAR_CONF_FILE
		$SED "s?^RELAY_DHCP_IP.*?RELAY_DHCP_IP=$RELAY_DHCP_IP?g" $ALCASAR_CONF_FILE
		$SED "s?^RELAY_DHCP_PORT.*?RELAY_DHCP_PORT=$RELAY_DHCP_PORT?g" $ALCASAR_CONF_FILE
		/usr/bin/systemctl restart chilli
		;;
	*)
		echo "Argument inconnu :$1";
		echo "$usage"
		exit 1
		;;
esac

