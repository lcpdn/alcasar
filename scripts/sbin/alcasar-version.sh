#!/bin/bash
# $Id: alcasar-version.sh 1056 2013-03-26 21:46:36Z stephane $

# alcasar-version-list.sh
# by Richard REY
# This script is distributed under the Gnu General Public License (GPL)

# récupère les versions d'ALCASAR (stable et développement)
# download the ALCASAR versions (stable / dev)

VERSION="/var/www/html/VERSION"
SITE_VERSION="version.alcasar.net"
MAJ="False"
DNS_VERSION_L=`dig $SITE_VERSION txt | grep ^$SITE_VERSION | cut -d"\"" -f2`
DNS_VERSION=`echo $DNS_VERSION_L|cut -d" " -f1`
MAJ_DNS_VERSION=`echo $DNS_VERSION|cut -d"." -f1`
MIN_DNS_VERSION=`echo $DNS_VERSION|cut -d"." -f2`
UPD_DNS_VERSION=`echo $DNS_VERSION|cut -d"." -f3`
RUNNING_VERSION=`cat $VERSION|cut -d" " -f1`
MAJ_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f1`
MIN_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f2|cut -c1`
UPD_RUNNING_VERSION=`echo $RUNNING_VERSION|cut -d"." -f3`

#compare major number
if [ $MAJ_RUNNING_VERSION -lt $MAJ_DNS_VERSION ]
then
	MAJ="True"
fi
#compare minor number
if [ $MAJ_RUNNING_VERSION -eq $MAJ_DNS_VERSION ] 
then
	if [ $MIN_RUNNING_VERSION -lt $MIN_DNS_VERSION ]
	then
		MAJ="True"
	fi
#compare update number
	if [ $MIN_DNS_VERSION -eq $MIN_RUNNING_VERSION ]
	then
		if [ -n "$UPD_DNS_VERSION" ]
		then
			if [ -z "$UPD_RUNNING_VERSION" ]
			then
				MAJ="True"
			else
		       		if [ $UPD_RUNNING_VERSION -lt $UPD_DNS_VERSION ]
				then
					MAJ="True"
				fi
			fi
		fi
	fi
fi

if [ $MAJ = "True" ]
	then 
		echo "An updated version is available ($DNS_VERSION)"
	else 
		echo "The Running version ($RUNNING_VERSION) is up to date"
fi
