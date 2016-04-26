#/bin/bash
# $Id: alcasar-profil.sh 1769 2016-01-17 20:39:23Z richard $

# alcasar-profil.sh
# by Richard REY
# This script is distributed under the Gnu General Public License (GPL)

# Gestion des comptes liés aux profiles
# Manage the profil logins

ADM_PROFIL="admin"
PROFILS="backup manager"
ALL_PROFILS=`echo $ADM_PROFIL $PROFILS`
DIR_KEY="/usr/local/etc/digest"
SED="/bin/sed -i"
HOSTNAME=`uname -n`
Lang=`echo $LANG|cut -c 1-2`

# liste les comptes de chaque profile
function list () {
	for i in $ALL_PROFILS
	do
		if [ $Lang == "fr" ]
       		then
			echo -n "Comptes liés au profil '$i' : "

		else
	       		echo -n "accounts linked with profile '$i' : "
		fi
		account_list=`cat $DIR_KEY/key_only_$i | cut -d':' -f1|sort`
		for account in $account_list
		do
			echo -n "$account " 
		done
	echo
	done
}
# ajoute les comptes du profil "admin" aux autres profils
# crée le fichier de clés contenant tous les compte (pour l'accès au centre de gestion)
function concat () {
	> $DIR_KEY/key_all
	for i in $PROFILS
	do
		cp -f $DIR_KEY/key_only_$ADM_PROFIL $DIR_KEY/key_$i
		cat $DIR_KEY/key_only_$i >> $DIR_KEY/key_$i
		cat $DIR_KEY/key_only_$i >> $DIR_KEY/key_all
	done
	cp -f $DIR_KEY/key_only_$ADM_PROFIL $DIR_KEY/key_$ADM_PROFIL
	cat $DIR_KEY/key_only_$ADM_PROFIL >> $DIR_KEY/key_all
	chown -R root:apache $DIR_KEY
	chmod 640 $DIR_KEY/key_*
}

usage="Usage: alcasar-profil.sh [-l|--list] [-a|--add] [-d|--del] [-p|--pass]"
nb_args=$#
args=$1

# on met en place la structure minimale
if [ ! -e $DIR_KEY/key_$ADM_PROFIL ]
then
	touch $DIR_KEY/key_$ADM_PROFIL
fi
cp -f $DIR_KEY/key_$ADM_PROFIL $DIR_KEY/key_only_$ADM_PROFIL
for i in $PROFILS
do
	if [ ! -e $DIR_KEY/key_only_$i ]
	then
		touch $DIR_KEY/key_only_$i
	fi
done
concat
if [ $nb_args -eq 0 ]
then
	echo $usage
	exit 0
fi
case $args in
	-\? | -h* | --h*)
		echo "$usage"
		exit 0
		;;
	--add|-a)	
		# ajout d'un compte
		list
		if [ $Lang == "fr" ]
	       	then
			echo -n "Choisissez un profil ($ALL_PROFILS) : "
		else
			echo -n "Select a profile ($ALL_PROFILS) : "
		fi
		read profil
		if [ $Lang == "fr" ]
		then
			echo -n "Entrez le nom du compte à créer (profil '$profil') : "
		else
		       	echo "Enter the name of the account to create (profile '$profil') : "
		fi
		read account
		# on teste s'il n'existe pas déjà
		for i in $ALL_PROFILS
		do
			tmp_account=`cat $DIR_KEY/key_only_$i | cut -d':' -f1`
			for j in $tmp_account
				do
				if [ "$j" = "$account" ]
					then if [ $Lang == "fr" ]
						then
							echo "Ce compte existe déjà"
						else
							echo "This account already exists"
						fi
					exit 0
				fi
				done
		done
		/usr/bin/htdigest $DIR_KEY/key_only_$profil $HOSTNAME $account
		concat
		list
		;;
	--del|-d)
		# suppression d'un compte
		list
		if [ $Lang == "fr" ]
		then
			echo -n "entrez le nom du compte à supprimer : "
		else
			echo -n "enter the name of the account to remove : "
		fi
		read account
		for i in $ALL_PROFILS
			do
			$SED "/^$account:/d" $DIR_KEY/key_only_$i
			done
		concat
		list
		;;
	--pass|-p)
		# changement du mot de passe d'un compte
		list
		if [ $Lang == "fr" ]
		then
			echo "Changement de mot de passe"
			echo -n "Entrez le nom du compte : "
		else
			echo "Password change"
			echo -n "Enter the name of the account : "
		fi
		read account
		for i in $ALL_PROFILS
		do
			tmp_account=`cat $DIR_KEY/key_only_$i | cut -d':' -f1`
			for j in $tmp_account
				do
				if [ "$j" = "$account" ]
					then
					/usr/bin/htdigest $DIR_KEY/key_only_$i $HOSTNAME $account
				fi
				done
		done
		concat
		;;
	--list|-l)
		# liste des comptes par profile
		list
		;;
	*)
		if [ $Lang == "fr" ]
		then
			echo "Argument inconnu :$1";
		else
			echo "Unknown argument : $i";
		fi
		echo "$usage"
		exit 1
		;;
esac
