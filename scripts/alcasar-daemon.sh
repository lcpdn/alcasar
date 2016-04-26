#!/bin/sh
# $Id: alcasar-daemon.sh 1596 2015-03-16 23:07:55Z richard $

# alcasar-daemon.sh
# by Franck BOUIJOUX & Rexy
# This script is distributed under the Gnu General Public License (GPL)
# Watchdog of Services
# See /etc/cron.d/alcasar-daemon-watchdog for config the time

conf_file="/usr/local/etc/alcasar.conf"
SSH=`grep SSH= $conf_file|cut -d"=" -f2`				# sshd active (on/off)
SSH=${SSH:=off}
SERVICES="mysqld httpd ntpd iptables dnsmasq dnsmasq-blacklist dnsmasq-whitelist dnsmasq-blackhole radiusd nfsen dansguardian freshclam ulogd-ssh ulogd-traceability ulogd-ext-access chilli fail2ban sshd"
nb_available_srv=`echo $SERVICES|wc -w`

function ServiceTest () {
	CMD=`/usr/bin/systemctl is-active $s`
	if [ $CMD != "active" ]
	then
		logger -i "!! $s is inactive. Activation attempt"
		echo "the $s service is disabled! trying to start it..."
	       	/usr/bin/systemctl start $s.service
	else
		nb_srv=$((nb_srv+1))
	fi
}

nb_srv=0
for s in $SERVICES
do
	if [ $s != "sshd" ] 
	then
		ServiceTest
	else
		{
		if [ $SSH == "ON" ] || [ $SSH == "on" ] || [ $SSH == "On" ]
	    	then
			ServiceTest
		else
			nb_available_srv=$((nb_available_srv-1))		
		fi
		}
	fi
done
if [ $nb_available_srv -ne $nb_srv ]
	then
	echo "restart this script to know if all is ok"
else
	echo "$nb_srv services are started. All is ok"
fi
