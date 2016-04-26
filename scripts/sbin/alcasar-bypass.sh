#!/bin/bash
# $Id: alcasar-bypass.sh 1739 2016-01-03 12:51:37Z richard $

# alcasar-bypass.sh
# by 3abtux and Rexy
# This script is distributed under the Gnu General Public License (GPL)

# activation / désactivation du contournement de l'authentification et du filtrage WEB
# enable / disable the bypass of authenticate process and filtering

usage="Usage: alcasar-bypass.sh {--on or -on } | {--off or -off}"
SED="/bin/sed -i"
CONF_FILE="/usr/local/etc/alcasar.conf"
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`				# INTernal InterFace

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
	--on | -on)	
		/usr/local/sbin/alcasar-logout.sh all
		/usr/bin/systemctl stop chilli
		cp -f /etc/sysconfig/network-scripts/bypass-ifcfg-$INTIF /etc/sysconfig/network-scripts/ifcfg-$INTIF
		ifup $INTIF
		sh /usr/local/bin/alcasar-iptables-bypass.sh
		DHCP=`grep ^DHCP= $CONF_FILE|cut -d"=" -f2`
		if  [ $DHCP != off ] 
		then 
			$SED "s?^#route.*?&?g" /etc/dnsmasq.conf # dnsmasq become the DHCP server
			$SED "s?^no-dhcp-interface.*?#&?g" /etc/dnsmasq.conf # 	
			/usr/bin/systemctl restart dnsmasq
		fi

		rm -f /etc/cron.d/alcasar-daemon-watchdog # don't restart daemons (specially coova) 
		echo "ALCASAR est en mode 'bypass'"
		echo "ALCASAR is in 'bypass' mode"
		;;
	--off | -off)
		cp -f /etc/sysconfig/network-scripts/default-ifcfg-$INTIF /etc/sysconfig/network-scripts/ifcfg-$INTIF
		ifup $INTIF
		$SED "s?^route.*?#&?g" /etc/dnsmasq.conf # 
		$SED "s?^#no-dhcp-interface=$INTIF?no-dhcp-interface=$INTIF?g" /etc/dnsmasq.conf
		$SED "s?^#no-dhcp-interface=tun0?no-dhcp-interface=tun0?g" /etc/dnsmasq.conf
		$SED "s?^#no-dhcp-interface=lo?no-dhcp-interface=lo?g" /etc/dnsmasq.conf
		/usr/bin/systemctl restart dnsmasq
		/usr/bin/systemctl start chilli
		sh /usr/local/bin/alcasar-iptables.sh
		# activation of the "daemon-watchdog" every 18'
		cat << EOF > /etc/cron.d/alcasar-daemon-watchdog
# activation du "chien de garde" (daemon-watchdog) toutes les 18'
*/18 * * * * root /usr/local/bin/alcasar-daemon.sh > /dev/null 2>&1
EOF
		echo "L'authentification et le filtrage sont actifs"
		echo "Authentication and filtering system are enabled"
;;
	*)
		echo "Argument inconnu :$1";
		echo "$usage"
		exit 1
		;;
esac
