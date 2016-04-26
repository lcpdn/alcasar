#!/bin/bash
# $Id: alcasar-archive.sh 1695 2015-09-08 07:37:46Z franck $

# alcasar-archive.sh
# by Franck BOUIJOUX and REXY
# This script is distributed under the Gnu General Public License (GPL)

# Script permettant 
#	- d'exporter dans un seul fichier les logs de traçabilités et la base des usagers (à des fins d'archivages).
# 	- Une fonction de chiffrement des logs a été implémentée dans ce script. Lisez la documentation d'exploitation pour l'activer.
#	- nettoyage des archives supérieures à 1 an (365 jours)

# This script allows 
#	- export in one file the log files and user's base (in order to archive them).
# 	- a cypher fonction allows to protect these files. Read the exploitation documentation to enable it.
#	- delete backup files older than one year (365 days)

DIR_SAVE="/var/Save"			# répertoire accessible par webs
DIR_LOG="/var/log"			# répertoire local des log

#DIR_SERVICE="squid httpd firewall"	# répertoires contenant des logs utiles à exporter
DIR_BASE="$DIR_SAVE/base"		# répertoire de sauvegarde de la base de données usagers
DIR_ARCHIVE="$DIR_SAVE/archive"		# répertoire de sauvegarde des archives de log
NOW="$(date +%G%m%d-%Hh%M)"  		# date et heure du moment
DIR_TMP="/tmp/traceability-$NOW"	# Répertoire temporaire d'export
FILE="traceability-$NOW.tar.gz"		# Nom du fichier de l'archive
EXPIRE_DAY=365				# Nbre de jour avant suppression des fichiers journaux
CRYPT="0"				# chiffrement des logs 		( 0=non / 1=oui) --> Si oui alors la signature est automatiquement activée
					# log files encryption		( 0=no / 1=yes) --> if yes, the signature is automaticly enabled 
SIGN="0"				# Signature/empreinte des logs 	( 0=non / 1=oui ) ATTENTION : nécessite la clé privée !!!
					# Signature of log files	( 0=no / 1=yes )  ATTENTION : need the private key !!!
GPG_USER=""				# utilisateur autorisé à déchiffrer les logs. Sa clé publique doit être connu dans le portefeuille gnupg de root (/root/.gnupg)
					# user allowed to decrypt the log files. Its public key must be known in the root keyring (/root/.gnupg)

usage="Usage: alcasar-archive.sh {--live or -l} | {--now or -n} | {--clean or -c}"

nb_args=$#
args=$1
if [ $nb_args -eq 0 ]
then
	nb_args=1
	args="-h"
fi


function cleanup() {
  # Nettoyage des fichiers archives
      cd $DIR_SAVE
      find . \( -mtime +$EXPIRE_DAY \) -a \( -name '*.gz' -o -name '*.sql' -o -name '' -o -name 'gpg'  \) -exec rm -f {} \;
} # end function cleanup


function crypt() {
	# Chiffrement des logs dans /var/Save/
	find . \( -mtime -7 -o -ctime 0 \) -a \( -name '*log-*.gz' \) -exec gpg --output $DIR_ARCHIVE/$file/{}.gpg --encrypt --recipient $GPG_USER {} \;
} # end function crypt

function archive() {
		mkdir -p $DIR_ARCHIVE
		mkdir -p $DIR_TMP 
		nb_files=`ls $DIR_LOG/firewall/traceability.log*.gz 2>/dev/null | wc -w`
		if [ $nb_files -ne 0 ]; then
			mv $(echo $(ls -rt $DIR_LOG/firewall/traceability.log*.gz | tail -n 1 -)) $DIR_TMP/traceability-HTTP-$NOW.gz
		fi
		nb_files=`ls $DIR_BASE/alcasar-users-database-*.sql.gz 2>/dev/null | wc -w`
		if [ $nb_files -ne 0 ]; then
			mv $(echo $(ls -rt $DIR_BASE/alcasar-users-database-*.sql.gz | tail -n 1 -)) $DIR_TMP/
		fi
		cd /var/log/nfsen/profiles-data/live/alcasar_netflow
		nb_files=`find . -mtime -7 -name 'nfcapd.[0-9]*' | wc -l`
		if [ $nb_files -ne 0 ]; then
			find .  -mtime -7 -name 'nfcapd.[0-9]*' | xargs tar -cf $DIR_TMP/traceability-ALL-$NOW.tar;
		fi
		cd /tmp/
		nb_files=`ls traceability-$NOW/* 2>/dev/null | wc -w`
		if [ $nb_files -ne 0 ]; then
			tar cvzf /tmp/$FILE traceability-$NOW/*
		else echo "no file to archive"
		fi
} # end archive

#  Core script
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	--clean | -c)	
# Cleanup of files older than 365 days
		cleanup
		;;
	--now | -n)
		
# Cleanup of files older than 365 days
		cleanup
# make an archive
		archive
# Saving of the database
		/usr/local/sbin/alcasar-mysql.sh --dump
# Encryption of the archive
 		if [ -e /tmp/$FILE ]; then 
			if [ $CRYPT -eq "1" ]; then
			{
				# 1 ) chiffrement/signature =1 ==> gpg --encrypt avec test de la clé présente
				gpg --output $DIR_ARCHIVE/$FILE-crypt.gpg --armor --encrypt --recipient $GPG_USER  /tmp/$FILE
			}
			elif [ $SIGN -eq "1" ]; then
			{
				# 2) signature = 1 Chiffrement = 0 --> gpg --encrypt   idem test de la clé présente
				gpg --output $DIR_ARCHIVE/$FILE-sign.gpg --sign --recipient $GPG_USER  /tmp/$FILE
				gpg --output $DIR_ARCHIVE/$FILE-sign.gpg --sign --recipient $GPG_USER --detach-sign  /tmp/$FILE
			}
			else
			{
				# 3)  chiffrement/signature = 0  --> cp simple avec suppression des droits d'écriture
				cp /tmp/$FILE $DIR_ARCHIVE/.
			}
			fi
		fi
		rm -rf /tmp/traceability-*
		chown root:apache $DIR_ARCHIVE/*
		;;
	--live | -l)
		mkdir -p $DIR_ARCHIVE
		mkdir -p /tmp/live 
		gap=$(($(date +%e)-1))
		cd /var/log/nfsen/profiles-data/live/alcasar_netflow
		find .  -mtime -$gap -name 'nfcapd.[0-9]*' | xargs tar -cf /tmp/live/traceability-ALL-$NOW.tar;
# Saving of the database
		/usr/local/sbin/alcasar-mysql.sh --dump
		mv $(echo $(ls -rt $DIR_BASE/alcasar-users-database-*.sql.gz | tail -n 1 -)) /tmp/live/
		cp /var/log/firewall/traceability.log /tmp/live/traceability-HTTP-$NOW.log
		tar -czf $DIR_ARCHIVE/traceability-$NOW.tar.gz /tmp/live/*
		rm -rf /tmp/live
		;;
	*)
		echo "Unknown argument :$1";
		echo "$usage"
		exit 1
		;;
esac
exit 0
