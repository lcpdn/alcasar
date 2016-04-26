#!/bin/bash

# alcasar-file-clean.sh
# by Rexy
# This script is distributed under the Gnu General Public License (GPL)

# clean alcasar conf files (remove empty lines, sort and control)
# nettoie les fichiers de conf d'alcasar (suppression des lignes vides, tri et contrôle)

SED="/bin/sed -i"
DIR_CONF="/usr/local/etc"
ALCASAR_SERVICES="$DIR_CONF/alcasar-services"
ALCASAR_IP_BLOCKED="$DIR_CONF/alcasar-ip-blocked"
ALCASAR_UAMDOMAIN="$DIR_CONF/alcasar-uamdomain"
ALCASAR_UAMALLOWED="$DIR_CONF/alcasar-uamallowed"
ALCASAR_CONF="$DIR_CONF/alcasar.conf"


# sort file content
for file in $ALCASAR_SERVICES $ALCASAR_IP_BLOCKED $ALCASAR_UAMDOMAIN $ALCASAR_UAMALLOWED
do
	sort -k2n $file > /tmp/alcasar-tmp-sort
	mv -f /tmp/alcasar-tmp-sort $file
done

# remove empty lines and put rights
for file in $ALCASAR_SERVICES $ALCASAR_EXCEPTIONS $ALCASAR_IP_BLOCKED $ALCASAR_CONF $ALCASAR_UAMDOMAIN $ALCASAR_UAMALLOWED
do
	$SED "/^$/d" $file 
	chown root:apache $file
	chmod 660 $file
done
