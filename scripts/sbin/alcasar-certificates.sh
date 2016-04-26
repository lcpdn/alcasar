#!/bin/sh

# Id: $Id$

# alcasar-certificates.sh
# by Franck BOUIJOUX and REXY
# This script is distributed under the Gnu General Public License (GPL)

# Script permettant 
#	- d'exporter les certificats d'un serveur pour les transposer sur un autre.

# This script allows 
#	- export certificates server to move them.


DIR_EXPORT="/root/Certificats"
DIR_PKI="/etc/pki"
DIR_SAVE="/root/PKI_SAVE"
DIR_IMPORT="/root/Certificats"


usage="Usage: alcasar-certificates.sh {--export or -x} | {--import or -i <FileOfCertificate.tar.gz>} "

nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	nb_args=1
	args="-h"
fi


NOW="$(date +%G%m%d-%Hh%M)"  		# date et heure du moment
FILE="certificates-$NOW"
DIR_SAVE=$DIR_SAVE-$NOW

# Function of export 
function certs_export() {
	#  Export of CA Certificate 
	cd /root
	tar cvf $FILE.tar  $DIR_PKI/CA/{alcasar-ca.crt,private/alcasar-ca.key}

	#  Export of server Certificate 
	tar rvf $FILE.tar $DIR_PKI/tls/{certs/alcasar.crt,private/alcasar.key,certs/server-chain.crt} 
	gzip $FILE.tar 
	echo "Le ficher des certificats exportés est : $FILE.tar.gz"
} # end function export


function archive() {
	# Sauvegarde de la pki actuelle
	[ -d $DIR_SAVE ] || mkdir $DIR_SAVE

	#  Save of CA Certificate 
	cd $DIR_PKI/CA/
	cp alcasar-ca.crt $DIR_SAVE/. 
	cp private/alcasar-ca.key $DIR_SAVE/. 

	#  Save of server Certificate 
	cd $DIR_PKI/tls
	cp certs/alcasar.crt $DIR_SAVE/. 
	cp private/alcasar.key $DIR_SAVE/. 
	cp certs/server-chain.crt $DIR_SAVE/. 
} # end function archive

function import() {
	echo "Would you like to Import New Certificates in ALCASAR ?"
	read response
	if [ $response = "y" ] || [ $response = "o" ] || [ $response = "Y" ] || [ $response = "O" ]
	then
		[ -d $DIR_IMPORT ] || mkdir $DIR_IMPORT
		rm -rf $DIR_IMPORT/*

		#  Import of CA Certificate 
		tar xzvf $1 --directory=$DIR_IMPORT
		echo "Import new certificates in ALCASAR !!!"
		cp -r $DIR_IMPORT/* /.
		chown root:apache $DIR_PKI/CA/{alcasar-ca.crt,private/alcasar-ca.key}
		chown root:apache $DIR_PKI/tls/{certs/alcasar.crt,private/alcasar.key,certs/server-chain.crt}

		# Service apache restart
		service httpd restart
	else 
	      echo "You are not import new certificates !!!"
	      exit 0
	fi
} # end import

#  Core script
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	--export | -x)	
		archive
		certs_export
		;;
	--import | -i)
		nb_args=$#
		if [ $nb_args -eq 1 ]
		then
			echo "Il faut passer un fichier de certificat en paramètre !!!"
			exit 0 
		fi
		import $2
		;;
	*)
		echo "Unknown argument :$1";
		echo "$usage"
		exit 1
		;;
esac
exit 0

