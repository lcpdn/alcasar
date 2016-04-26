#!/bin/bash
# $Id: alcasar-watchdog.sh 1688 2015-08-27 21:48:57Z richard $

# alcasar-watchdog.sh
# by Rexy
# This script is distributed under the Gnu General Public License (GPL)
# Ce script prévient les usagers de l'indisponibilité de l'accès Internet
# il déconnecte les usagers dont
# - les équipements réseau ne répondent plus
# - les adresses MAC sont usurpées
# This script tells users that Internet access is down
# it logs out users whose 
# - PCs are quiet
# - MAC address is used by other systems (usurped)

CONF_FILE="/usr/local/etc/alcasar.conf"
EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`			# EXTernal InterFace
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`			# INTernal InterFace
private_ip_mask=`grep PRIVATE_IP= $CONF_FILE|cut -d"=" -f2`
private_ip_mask=${private_ip_mask:=192.168.182.1/24}
PRIVATE_IP=`echo "$private_ip_mask" |cut -d"/" -f1`      # @ip du portail (côté LAN)
PRIVATE_IP=${PRIVATE_IP:=192.168.182.1}
tmp_file="/tmp/watchdog.txt"
DIR_WEB="/var/www/html"
Index_Page="$DIR_WEB/index.php"
IPTABLES="/sbin/iptables"
TUNIF="tun0"						# listen device for chilli daemon
OLDIFS=$IFS
IFS=$'\n'

function lan_down_alert ()
# users are redirected on ALCASAR IP address if a LAN problem is detected
{
	case $LAN_DOWN in
	"1")
		logger "$EXTIF (WAN card) link down"
		echo "$EXTIF (WAN card) link down"
		/bin/sed -i "s?diagnostic =.*?diagnostic = \"$EXTIF (WAN card) link down\";?g" $Index_Page
		;;
	"2")
		logger "can't contact the default router"
		echo "can't contact the default router"
		/bin/sed -i "s?diagnostic =.*?diagnostic = \"can't contact the default router\";?g" $Index_Page
		;;
	esac
	net_pb=`grep "network_pb = True;" $Index_Page|wc -l`
	if [ $net_pb = "0" ] # user alert (only the first time)	
		then
		/bin/sed -i "s?^\$network_pb.*?\$network_pb = True;?g" $Index_Page
		$IPTABLES -I PREROUTING -t nat -i $TUNIF -p udp --dport domain -j REDIRECT --to-port 56
	fi
}

function lan_test ()
# LAN connectiivity testing
{
	watchdog_process=`ps -C alcasar-watchdog.sh|wc -l`
	if [[ $(expr $watchdog_process) -gt 3 ]]
		then
		echo "ALCASAR watchdog is already running"
		exit 0
	fi
	# EXTIF testing
	LAN_DOWN="0"
	if [ `/sbin/ip link | grep $EXTIF|grep "NO-CARRIER" | wc -l` -eq "1" ]
		then
		LAN_DOWN="1"
	fi
	# Default GW testing
	if [ $LAN_DOWN -eq "0" ]
		then
		IP_GW=`/sbin/ip route list|grep ^default|cut -d" " -f3`
		arp_reply=`/usr/sbin/arping -I$EXTIF -c1 $IP_GW|grep response|cut -d" " -f2`
		if [ $arp_reply -eq "0" ]
	       		then
			LAN_DOWN="2"
		fi
	fi
	# if LAN pb detected, users are warned
	if [ $LAN_DOWN != "0" ]
		then
			lan_down_alert
	# else switch in normal mode
	else
		echo "Internet access is OK for now"
		net_pb=`grep "network_pb = True;" $Index_Page|wc -l`
		if [ $net_pb != "0" ]
			then
			/bin/sed -i "s?^\$network_pb.*?\$network_pb = False;?g" $Index_Page
			$IPTABLES -D PREROUTING -t nat -i $TUNIF -p udp --dport domain -j REDIRECT --to-port 56
		fi
	fi
}

usage="Usage: alcasar-watchdog.sh {-lt --lan_test}"
case $1 in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	-lt | --lan_test)
		lan_test
		exit 0
		;;
	*)
		lan_test
		# read file that contains IP address of quiet equipments
		if [ -e $tmp_file ]; then
			cat $tmp_file | while read noresponse
			do
				noresponse_ip=`echo $noresponse | cut -d" " -f1`
				noresponse_mac=`echo $noresponse | cut -d" " -f2`
				noresponse_user=`echo $noresponse | cut -d" " -f3`
				arp_reply=`/usr/sbin/arping -b -I$INTIF -s$PRIVATE_IP -c1 -w4 $noresponse_ip|grep "Unicast reply"|wc -l`
				if [[ $(expr $arp_reply) -eq 0 ]]
	       				then
					logger "alcasar-watchdog $noresponse_ip ($noresponse_mac) can't be contact. Alcasar disconnects the user ($noresponse_user)."
					/usr/sbin/chilli_query logout $noresponse_mac
					if [[ $noresponse_user == $noresponse_mac ]] # for @mac auth equipments, we must remove the arp entry 
						then /usr/sbin/chilli_query dhcp-release $noresponse_mac
					fi
				fi
			done
			rm $tmp_file
		fi
# process each equipment known by chilli
		for system in `/usr/sbin/chilli_query list |grep -v "\.0\.0\.0"`
		do
			active_ip=`echo $system |cut -d" " -f2`
			active_session=`echo $system |cut -d" " -f5`
			active_mac=`echo $system | cut -d" " -f1`
			active_user=`echo $system |cut -d" " -f6`
# process only equipment with an authenticated user
			if [[ $(expr $active_session) -eq 1 ]]
			then
				arp_reply=`/usr/sbin/arping -b -I$INTIF -s$PRIVATE_IP -c2 -w4 $active_ip|grep "Unicast reply"|wc -l`
# store @IP of quiet equipments
				if [[ $(expr $arp_reply) -eq 0 ]]
	       				then
					echo "$active_ip $active_mac $active_user" >> $tmp_file
				fi
# disconnect users whose equipement is usurped (@MAC)
				if [[ $(expr $arp_reply) -gt 2 ]]
	       				then 
					echo "$(date "+[%x-%X] : ")alcasar-watchdog : $active_ip is usurped ($active_mac). Alcasar disconnect the user ($active_user)." >> /var/Save/security/watchdog.log
					logger "alcasar-watchdog : $active_ip is usurped ($active_mac). Alcasar disconnect the user ($active_user)."
					/usr/sbin/chilli_query logout $active_mac
					chmod 644 /var/Save/security/watchdog.log
				fi
			fi
		done
		;;
esac	
IFS=$OLDIFS
