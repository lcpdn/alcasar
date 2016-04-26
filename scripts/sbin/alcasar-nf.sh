#/bin/bash
# $Id: alcasar-nf.sh 1056 2013-03-26 21:46:36Z stephane $

# alcasar-nf.sh
# by Rexy
# This script is distributed under the Gnu General Public License (GPL)

# active ou desactive le filtrage de protocoles réseau
# enable or disable the network protocols filter

SED="/bin/sed -i"
FIC_CONF="/usr/local/etc/alcasar.conf"

usage="Usage: alcasar-nf.sh {--on | -on} | {--off | -off}"
nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	echo $usage
	exit 1
fi
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	-on|-on) # enable protocols filter
		$SED "s?^PROTOCOLS_FILTERING.*?PROTOCOLS_FILTERING=on?g" $FIC_CONF
		/usr/local/bin/alcasar-iptables.sh
		;;
	--off|-off) # disable protocols filter
		$SED "s?^PROTOCOLS_FILTERING.*?PROTOCOLS_FILTERING=off?g" $FIC_CONF
		/usr/local/bin/alcasar-iptables.sh
		;;
	*)
		echo "Argument inconnu :$1";
		echo "$usage"
		exit 1
		;;
esac

