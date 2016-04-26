#!/bin/sh

# alcasar-conup.sh
# by Rexy
# This script is distributed under the Gnu General Public License (GPL)

# This script is launched after each successfull login
# Ce script est lancé à chaque connexion d'usager (authentification réussi)

# Debug : show all the coova parse variables. There are declared in /src/chilli.c
#echo "parse coova variables" > /tmp/debug-conup.txt
#for i in LAYER3 DEV NET MASK ADDR USER_NAME NAS_IP_ADDRESS SERVICE_TYPE FRAMED_IP_ADDRESS FILTER_ID STATE CLASS CUI SESSION_TIMEOUT IDLE_TIMEOUT CALLING_STATION_ID CALLED_STATION_ID NAS_ID NAS_PORT_TYPE ACCT_SESSION_ID ACCT_INTERIM_INTERVAL WISPR_LOCATION_ID WISPR_LOCATION_NAME WISPR_BANDWIDTH_MAX_UP WISPR_BANDWIDTH_MAX_DOWN WISPR-SESSION_TERMINATE_TIME CHILLISPOT_MAX_INPUT_OCTETS CHILLISPOT_MAX_OUTPUT_OCTETS CHILLISPOT_MAX_TOTAL_OCTETS INPUT_OCTETS OUTPUT_OCTETS SESSION_TIME IDLE_TIME LOCATION OLD_LOCATION TERMINATE_CAUSE
#do
#	echo "$i : ${!i}" >> /tmp/debug-conup.txt
#done

# Add user to the SET (function of his filtering level)
case $FILTER_ID in
	# HAVP
	"00000001")
		set="havp_set"
		;;
	# HAVP + Blacklist
	"00000011")
		set="havp_bl_set"
		;;
	# HAVP + Whitelist
	"00000101")
		set="havp_wl_set"
		;;
	# No filtering
	*)
		set="no_filtering_set"
		;;
esac
ipset add $set $FRAMED_IP_ADDRESS
