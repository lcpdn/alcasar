#/bin/bash
# $Id: alcasar-logout.sh 1056 2013-03-26 21:46:36Z stephane $

# alcasar-logout.sh
# by Rexy
# This script is distributed under the Gnu General Public License (GPL)

# Déconnexion d'un ou de tous les usagers
# Logout one user (or all users)

radiussecret=""
OLDIFS=$IFS
IFS=$'\n'

usage="Usage: alcasar-logout.sh {user_name} | {all}"
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
	all)
# Compute each equipments known by chilli
		for system in `/usr/sbin/chilli_query list |grep -v "\.0\.0\.0"`
		do
			logout_users=""
			active_session=`echo $system |cut -d" " -f5`
			active_user=`echo $system|cut -d" " -f6`
			active_mac=`echo $system | cut -d" " -f1`
# Logout only authenticated users 
			if [[ $(expr $active_session) -eq 1 ]]
			then
# Don't logout MAC authenticated 
				if [ "$active_mac" != "$active_user" ]
				then
					logout_users=$logout_users" $active_user"
					/usr/sbin/chilli_query logout $active_mac
				fi
			fi
		done
		echo "All users are now logout : ($logout_users)"
		;;
	*)
		echo "User-Name = $args" | /usr/bin/radclient 127.0.0.1:3799 40 $radiussecret
		;;
esac
IFS=$OLDIFS

