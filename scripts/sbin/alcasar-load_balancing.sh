#!/bin/bash
# $Id: alcasar-load_balancing.sh 1469 2014-10-30 21:58:47Z richard $

# Generic Load balancer for multiple WAN links - version 1.1 (04 Feb 2011)
# (c) 2011 Pau Oliva Fora - http://pof.eslack.org
#
# Licensed under GPLv3 - for full terms see:
# http://www.gnu.org/licenses/gpl-3.0.html
#
# Adapted and debugged (adr et ping -S) by ALCASAR Team (3abtux@alcasar.net)
# (c) 2013  3abtux - http://www.alcasar.net
#
# Specify each WAN link in a separate column, example:
# In this example we have 3 wan links (vlanXXX interfaces) attached to a single
# physical interface because we use a vlan-enabled switch between the balancer
# machine and the ADSL routers we want to balance. The weight parameter should
# be kept to a low integer.
#
#
# Modified by ALCASAR team :


prog="alcasar-load_balancing.sh"
pidfile="/var/run/alcasar-load_balancing.pid"

###############################
# MAIN PARAMETERs Configuration
###############################

DIR_ETC="/usr/local/etc"
CONF_FILE="$DIR_ETC/alcasar.conf"
MULTIWAN=`grep MULTIWAN= $CONF_FILE|cut -d"=" -f2`
MULTIWAN=${MULTIWAN:=off}
FAILOVER=`grep FAILOVER= $CONF_FILE|cut -d"=" -f2`
FAILOVER=${FAILOVER:=30}
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`				# INTernal InterFace


# space separated list of public IPs to ping in watchdog mode
# set this to some public ip addresses pingable and always on.
TESTIPS="8.8.8.8 192.0.32.10"

# set to 1 when testing, set to 0 when happy with the results
VERBOSE=0

# CONFIGURATION ENDS HERE
###############################


if [ $(whoami) != "root" ]; then
        echo "You must be root to run this!" ; echo ; exit 1
fi

# Adapter for ALCASAR project
CONF_FILE="/usr/local/etc/alcasar.conf"

# Virtual interfaces creating
function create_eth () {
	routecmd="ip route replace default scope global"
	NBIFACE=`grep "^WAN" $CONF_FILE | wc -l`	# Nbre interfaces virtuelles
	i=0
	while [ $i -le $NBIFACE ]
	do
		INT="WAN$i"
		echo $INT
		ACTIVE=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $1}'`	# Active
		WT=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $5}'`		# WEIGHT
		WT=${WT:-1}
		IP=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $3}' | cut -d"/" -f1`	# @IP

		if [ $i -ne 0 ]; then
			[ -e /etc/sysconfig/network-scripts/ifcfg-$INTIF:$i ] && ifdown $INTIF:$i && rm -f /etc/sysconfig/network-scripts/ifcfg-$INTIF:$i
			IFACE=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $2}'`	# IFACE
			IP_NET=`grep "^$INT=" $CONF_FILE | awk -F'"' '{print $2}' | awk -F, '{ print $3}'`	# IP
			NET="`ipcalc -n $IP_NET | cut -d"=" -f2`/`ipcalc -p $IP_NET|cut -d"=" -f2`"
			GW=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $4}'`		# @GW
			MTU=`grep "$INT=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $6}'`	# MTU

			# Config $INTIF:$i (Internet)
			cat <<EOF > /etc/sysconfig/network-scripts/ifcfg-$INTIF:$i
DEVICE=$IFACE
BOOTPROTO=static
IPADDR=`echo $IP | cut -d"/" -f1`
NETMASK=`ipcalc -m $IP_NET | cut -d= -f2`
NETWORK=`ipcalc -n $IP_NET | cut -d= -f2`
MTU=$MTU
ONBOOT=yes
NOZEROCONF=yes
MII_NOT_SUPPORTED=yes
IPV6INIT=no
IPV6TO4INIT=no
ACCOUNTING=no
USERCTL=no
EOF
			echo "ifup $INTIF:$i"
			ifup $INTIF:$i
			NET="`ipcalc -n $IP_NET | cut -d"=" -f2`/`ipcalc -p $IP_NET|cut -d"=" -f2`"
		else
			IFACE="$INTIF"
			IP_NET=`grep "^PUBLIC_IP=" $CONF_FILE | awk -F'=' '{print $2}'`			# IP/MSK
			IP=`grep "^PUBLIC_IP=" $CONF_FILE | awk -F= '{ print $2 }' | cut -d"/" -f1`	# @IP
			GW=`grep "^GW=" $CONF_FILE | awk -F= '{print $2}'`				# @GW
#			MTU=`grep "^PUBLIC_MTU=" $CONF_FILE | awk -F= '{print $2}'`			# MTU
		fi # End

		NET="`ipcalc -n $IP_NET | cut -d"=" -f2`/`ipcalc -p $IP_NET|cut -d"=" -f2`"
		if [ "$PARAM" == "add" ]; then	
			set -x
			table=$(($i + 1))
			ip route ${PARAM} ${NET} dev ${IFACE} src ${IP} table $table
			ip route ${PARAM} default via ${GW} table $table
			ip rule ${PARAM} from ${IP} table $table
			set +x
		fi
		echo "	Iface: ${IFACE}"
		echo "	IP: ${IP}"
		echo "	IP_NET: ${IP_NET}"
		echo "	NET: ${NET}"
		echo "	GW: ${GW}"
		echo "	Weight: ${WT}"
		echo "	MTU : ${MTU}"
		echo
		routecmd="${routecmd} nexthop via ${GW} dev ${IFACE} weight ${WT}"
		i=$(($i + 1))
	done # End While

	if [ "$PARAM" == "add" ]; then	
		echo "[] Balanced routing:"
		# suppress default route
		ip route del default scope global
		set -x
		${routecmd}
		set +x
		echo
	fi
	
} # end create_eth

###########################
# Fonction virtual Interfaces deleting
###########################
delete_eth () {
	IFACE_COUNT=`ls -l /etc/sysconfig/network-scripts/ifcfg-$INTIF:* | wc -l`
	echo $IFACE_COUNT
	while [ $IFACE_COUNT -ne 0 ]
	do
		i=$IFACE_COUNT	
		echo "ifdown $INTIF:$i"
		ifdown $INTIF:$i
		rm -f /etc/sysconfig/network-scripts/ifcfg-$INTIF:$i
		IFACE_COUNT=$(($IFACE_COUNT - 1))
	done
	ip route del default scope global
#	ip route add default gw 192.168.1.1
}
	

# do not modify below this line unless you know what you're doing :)
function getvalue() {
        index=$1
        VAR=$2

        n=1
        for f in ${VAR} ; do
                if [ "${n}" == "${index}" ]; then
                        echo "$f"
                        break
                fi
                n=$(($n++))
        done
}

######################
# Fonction de FailOver
######################
function failover () {

	echo "[] Watchdog started"
	# 0 == all links ok, 1 == some link down
	STATE=0
	
	DOWNCOUNT_BAK=0
	DOWN_BAK=""
	NBIFACE=`grep "^WAN" $CONF_FILE | wc -l`	# Nbre interfaces virtuelles
	echo "Nombre interfaces =  "$NBIFACE
	WANIFACE[0]="$INTIF"
	c=0
	while [ $c -le $NBIFACE ]; do
		ITH=(`grep "WAN$c=" $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $2}'`)	# IFACE
		echo $ITH
		WANIFACE="${WANIFACE} $ITH"
		echo $WANIFACE
		c=$(($c + 1))
	done
	echo "Liste des interfaces : "${WANIFACE[*]}
	# Failover test
	while : ; do
	
		if [ $VERBOSE -eq 1 ]; then
			echo "[] Sleeping, state=$STATE"
		fi
		sleep $FAILOVER
	
		IFINDEX=1
		DOWN=""			# liste des interfaces down
		DOWNCOUNT=0		# nombre d'interface down
		for iface in $WANIFACE ; do
			COUNT=0		# compteur de test
			FAIL=0		# Nombre de fois down
			# Recup de l'adresse IP dynamiquement
			IP=`ifconfig $iface |grep "inet adr" |cut -f 2 -d ":" |awk '{print $1}'`
			if [ $i -ne 0 ]; then
				GW=`grep "$iface," $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $4}'`		# @GW
				WT=`grep "$iface," $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $5}'`		# @WT
			else
				GW=`grep "^GW=" $CONF_FILE | awk -F= '{print $2}'`			# @GW
			fi	
			for TESTIP in $TESTIPS ; do
				COUNT=$(($COUNT + 1))
				ping -W 3 -I $IP -c 1 $TESTIP > /dev/null 2>&1
#				ping -W 3 -I $IP -c 1 $TESTIP
				# Si ping de la première adresse --> ok  --> stop du test pour l'interface testée
				if [ $? -eq 0 ]; then
					break
				else 
					# sinon on compte une erreur
					FAIL=$(($FAIL + 1))
				fi
			done # End of test sur un serveur Internet
			# Affichage du nombre de down
			echo "FAIL=$FAIL"
			# Si nombre de fois down = nombre de tests -->  Iface down --> log dans fichier log avec l'heure
			if [ $FAIL -eq $COUNT ]; then
				echo "`date +%F-%Hh%mm%Ss` : [WARN] $iface is down!"
				# Si etat différent de 1 (déjà tombé) --> changement de l'état général en default
				if [ $STATE -ne 1 ]; then
					echo "Switching state $STATE -> 1"
					STATE=1
				fi
				# Rajout de l'iface dans la liste des interfaces down
				DOWN="${DOWN} $IFINDEX"
				echo "DOWN=$DOWN"
				# Nombre d'interface down
				DOWNCOUNT=$(($DOWNCOUNT + 1))
				echo "DOWNCOUNT=$DOWNCOUNT"
			fi
			IFINDEX=$(($IFINDEX + 1))
			echo "IFINDEX =$IFINDEX"
		done # End Test Interface in WANIFACE

		#  0 Passerelle down et état précédent différent (retour à la normale)) --> mise à la normale des passerelles 
#		if [ $DOWNCOUNT -eq 0 ] && [ $DOWNCOUNT -ne $DOWNCOUNT_BAK ]; then
		if [ $DOWNCOUNT -eq 0 ] ; then
			if [ $STATE -eq 1 ]; then
				echo
				echo "[] All links up and running :)"
				set -x
				${routecmd}
				set +x
				# Changement de l'état en normal
				STATE=0
				echo "Switching state 1 -> 0"
			fi # End retour etat normal
			# if no interface is down, go to the next cycle
			continue
		# cas ou au moins une passerelle down mais état identique au précédent Test --> rien à changer
		else
			if [ "$DOWN_BAK" == "$DOWN" ]; then
			echo "DOWN_BAK == DOWN = $DOWN"
				continue	# --> état identique test precedent --> boucle suivante
		# cas ou au moins une passerelle down mais état différent de test précédent --> remplacement par nouvelle règle
			else
				cmd="ip route replace default scope global"
				IFINDEX=1
				suffix=""
				# Pour chaque interface --> traitement et application de la règle de routage
				for iface in $WANIFACE ; do
					echo "-------------------------"
					echo "iface=$iface"
					echo "Index = " $IFINDEX
					FAILIF=0
					# Pour chaque interface down --> 
					echo "Interfaces DOWN = $DOWN"
					for lnkdwn in $DOWN ; do
						echo "LINKDOWN = "$lnkdown
						if [ $lnkdwn -eq $IFINDEX ]; then
							FAILIF=1
							break			
						else
							continue
						fi
					done # End linkdown in DOWN
					# Interface en etat normal --> rajout de la règle en mode nexthop
					if [ $FAILIF -eq 0 ]; then
						IP=`ifconfig $iface |grep "inet adr" |cut -f 2 -d ":" |awk '{print $1}'`
						if [ $iface != "$INTIF" ]; then
							GW=`grep "$iface," $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $4}'`		# @GW
							WT=`grep "$iface," $CONF_FILE | awk -F'"' '{ print $2 }' | awk -F, '{ print $5}'`		# @GW
						else
							GW=`grep "^GW=" $CONF_FILE | awk -F= '{print $2}'`			# @GW
						fi	
						echo "GW=$GW"
						echo "WT=$WT"
						echo "suffix=$sufix"
						suffix="${suffix} nexthop via ${GW} dev ${iface} weight ${WT:-1}"
					fi # End interface = noFAIL
					IFINDEX=$(($IFINDEX + 1))
				done # End  iface IN WANIFACE
				# Commande globale
				cmd="ip route replace default scope global $suffix"
			
				if [ $VERBOSE -eq 1 ]; then
					set -x
			#		echo "Avec commentaire : " ${cmd}
					${cmd}
					set +x
					echo
				else
					${cmd} 2>/dev/null
					echo ${cmd}
				fi # end Application de la commande de routage globale
			fi #
			DOWN_BAK=$DOWN	# Enregistrement de l'etat
		fi # End 
	done
} # End of Failover


#################
# Main
#################

echo "[] Load balancer for multiple WAN interfaces - v2.1"
echo "[] (c) 2011 Pau Oliva Fora <pof> @eslack.org"
echo "[] (c) 2013 3abtux ALCASAR  <3abtux> @alcasar.net"
echo

case $1 in
	create) 
		create_eth  		
	;;
	delete) 
		delete_eth  		
	;;
	start) 
                if [ "$MULTIWAN" != "on" ] && [ "$MULTIWAN" != "On" ]; then 
		    echo "The MultiGateway is not activated !"
		    exit 0
		fi
                PARAM="add"
                create_eth
                ip route flush cache
                if [ $FAILOVER -eq 0 ]; then 
		      echo "The MultiWAN Mode is actived but not failover connectivity !"
		      exit 0
		fi
                echo "Starting down $prog: "
                pid=`pidof -x "alcasar-load_balancing.sh"`
                if [ $pid != "" ]; then
                        echo $pid > $pidfile
                fi
                touch /var/lock/subsys/alcasar-load_balancing
                failover
	;;
	stop) 
		PARAM="del"
		echo "Shutting down $prog: "
                if [ -f $pidfile ]; then
                        pid=`cat $pidfile`
                        kill -9 $pid
                else
                        echo "$prog is not running."
                        exit 1
                fi
                RETVAL=$?
                echo
                [ $RETVAL -eq 0 ] && rm -f $pidfile && rm -f /var/lock/subsys/alcasar-load_balancing
                echo "Delete of virtual interfaces"
                delete_eth
                echo "Network restart"
                service network restart 2>&1 > /dev/null
                ip route
       
	;;
	status)
                echo "Checking  $prog : "
                if [ -f $pidfile ]; then
                        pid=`cat $pidfile`
                        CHECK=`ps -p $pid --no-heading | awk {'printf $1'}`
                        if [ "$CHECK" = "" ]; then
                                echo "$prog is NOT running."
                        else
                                echo "$prog is running !"
                        fi
                else
                                echo "$prog is Not running."
                fi	
	;;
	fail) 
		failover 		
	;;
	*) 
		echo "Usage: $0 [start|stop|status|create|delete]" ; echo ; exit 1
	;;
esac

exit 0
