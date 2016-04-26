#!/bin/bash

# alcasar-sms.sh
# by Nicolas Aubry & Rexy
# This script is distributed under the Gnu General Public License (GPL)

# This script manages the 'gammu-smsd' service when a GSM adapter is detected
# Ce script gère le service 'gammu-smsd' quand un adaptateur GSM est détecté

#########################################
#######	VARIABLES ########
nb_essais=3
time_account=1
time_ban=2
#########################################
####### IDs DB ##########################
u_db="radius"
p_db="password"
#########################################
#########################################

rad="radcheck"
radgp="radusergroup"
radgpck="radgroupcheck"
radinf="userinfo"

sms_p="SMS_ban_perm"
sms_t="SMS_ban_temp"

inb="inbox"
SMS_c="SMS_country"

config="/etc/gammu_smsd_conf"
logfile="/var/log/gammu-smsd/gammu-smsd.log"
script="/usr/local/bin/alcasar-sms.sh"
public_page="/var/www/html/autoregistrationinfo.php"
index_page="/var/www/html/index.php"
intercept_page="/var/www/html/intercept.php"
separator="########## START ##########"
end="%%%%%%%%%% STOP %%%%%%%%%%"


usage="Usage: alcasar-gammu.sh 
Start Gammu-smsd   : --start
Stop Gammu-smsd    : --stop 
Process on new sms : --new_sms"


nb_args=$#
args=$1


# Functions
function mode_huawei() {
	couple=$(lsusb | grep -i huawei | cut -d ' ' -f6)
	vendor=$(echo $couple | cut -d ':' -f1)
	product=$(echo $couple | cut -d ':' -f2)

	echo "*********************" >> /srv/log.log
	echo $vendor >> /srv/log.log
	echo $product >> /srv/log.log

	/usr/sbin/usb_modeswitch -I -H -v 0x$vendor -p 0x$product -V 0x$vendor -P 0x$product -W -n >> /srv/log.log
}

function start_gammu() {
	#On truncate la table phones (informations signal / IMEI / batterie / sms recu et envoyé)
		sql_trunc_phones="connect gammu; TRUNCATE phones;"
		result=$(mysql --user=$u_db --password=$p_db -B -se "$sql_trunc_phones")


	#On verifie que le groupe sms est créé
		sql_check_gp="connect radius; SELECT * FROM $radgp WHERE username='sms' AND groupname='sms';"
		result=$(mysql --user=$u_db --password=$p_db -B -se "$sql_check_gp")

		if test -z "$result"
		then
			sql_add_gp="connect radius; INSERT INTO $radgp (username,groupname) VALUES ('sms','sms');"
			sql_add_gp_att="connect radius; INSERT INTO $radgpck (groupname,attribute,op,value) VALUES ('sms','Simultaneous-Use',':=',1);"
		
			mysql --user=$u_db --password=$p_db -B -se "$sql_add_gp"
			mysql --user=$u_db --password=$p_db -B -se "$sql_add_gp_att"
		fi

	#Start gammu
		echo $separator >> $logfile
		sudo gammu-smsd --config $config --pid /var/run/gammu-smsd.pid --daemon
} # end function start_gammu

function stop_gammu() {
	#Stop gammu
		sudo kill -9 gammu-smsd
		sleep 10
		echo $end >> $logfile
} # end function stop_gammu

function unlock() {
	#Suppression du numero dans la table SMS_ban_perm
		sql_remove_ban_perm="connect gammu; DELETE FROM $sms_p"
		mysql --user=$u_db --password=$p_db -B -se "$sql_remove_ban_perm WHERE SenderNumber=$1;"
				
	# Ajout au groupe sms
		sql_remove_gp="connect radius; DELETE FROM $radgp WHERE username='$1';"
		mysql --user=$u_db --password=$p_db -B -se "$sql_remove_gp"
	
	# Suppression du compte dans Radcheck
		sql_remove_compte="connect radius; DELETE FROM $rad WHERE username='$1';"
		mysql --user=$u_db --password=$p_db -B -se "$sql_remove_compte"
} # end function unlock

function change_country() {
	# recupère le status du pays
		sql_status_country="connect gammu; SELECT status FROM SMS_country WHERE name='$1'"
		stat=$(mysql --user=$u_db --password=$p_db -B -se "$sql_status_country")

		if [ $stat -eq 0 ]
		then
			sql_change_country="connect gammu; UPDATE $SMS_c SET status=1 WHERE name='$1'"
			mysql --user=$u_db --password=$p_db -B -se "$sql_change_country"
		else
			sql_change_country="connect gammu; UPDATE $SMS_c SET status=0 WHERE name='$1'"
			mysql --user=$u_db --password=$p_db -B -se "$sql_change_country"
		fi


} # end change_country

function supp_acc_rad() {
	# Suppression du compte dans Radcheck
		sql_del_compte="connect radius; DELETE FROM $rad WHERE username='$1';"
		mysql --user=$u_db --password=$p_db -B -se "$sql_del_compte"
} # end function supp_acc_rad()

function add_acc_rad() {
	# Ajout table RadCheck : creation du compte
		sql_add_pass="connect radius; INSERT INTO $rad (username,attribute,op,value) VALUES ('$1','Crypt-Password',':=','$2');"
		sql_add_expe="connect radius; INSERT INTO $rad (username,attribute,op,value) VALUES ('$1','Expiration',':=','$3');"
		
		mysql --user=$u_db --password=$p_db -B -se "$sql_add_pass"
		mysql --user=$u_db --password=$p_db -B -se "$sql_add_expe"
			
	# Ajout au groupe sms
		sql_add_gp="connect radius; INSERT INTO $radgp (username,groupname) VALUES ('$1','sms');"
		mysql --user=$u_db --password=$p_db -B -se "$sql_add_gp"
} # end function add_acc_rad()
		
function supp_num_temp() {
	# Suppression du numéro dans table SMS_ban_temp
		sql_remove_ban_temp="connect gammu; DELETE FROM $sms_t"
		mysql --user=$u_db --password=$p_db -B -se "$sql_remove_ban_temp WHERE SenderNumber=$1;"
} # end function supp_num_temp()
	
function add_num_perm() {
	# Ajout du numero table SMS_ban_perm, 0 : creation du compte
		sql_add_ban_perm="connect gammu; INSERT INTO $sms_p (SenderNumber,Perm,Expiration) VALUES ('$1',0,'$2');"
		mysql --user=$u_db --password=$p_db -B -se "$sql_add_ban_perm"
} # end function add_num_perm()

function supp_num_perm() {
	#Suppression du numero dans la table SMS_ban_perm
		sql_remove_ban_perm="connect gammu; DELETE FROM $sms_p"
		mysql --user=$u_db --password=$p_db -B -se "$sql_remove_ban_perm WHERE SenderNumber=$1;"
} # end function add_num_perm()

function new_sms() {
	# Check Inbox table, manage Ban temp and perm, create account
		export salt='$1$passwd$'
	
		sql_select_inbox="connect gammu; SELECT ID, SenderNumber, TextDecoded FROM $inb;"
		sql_delete_inbox="connect gammu; DELETE FROM $inb"
		
		mysql --user=$u_db --password=$p_db -B -se "$sql_select_inbox" | while read result;
		do
		# On recupère le nombre de mots (resultat)
			nb=$(echo $result | wc -w)
			
		# On récupère le numéro de l'ID
				id=$(echo $result | cut -d ' ' -f1)

		numero=$(echo $result | cut -d ' ' -f2)

		if [[ $numero =~ ^\+ ]] 
		then
	
			# On vérifie si le pays est bloqué		
				sql_select_countries="connect gammu; SELECT id FROM $SMS_c WHERE status=1"
				mysql --user=$u_db --password=$p_db -B -se "$sql_select_countries" | while read result_c;
				do

				if [[ $numero =~ ^"$result_c" ]]
				then		

				numero=$(echo $numero | cut -d '+' -f2)

				# On vérifie que le numéro n'est pas Ban Perm	
					sql_ban_perm="connect gammu; SELECT * FROM $sms_p WHERE SenderNumber=$numero"
					result_bp=$(mysql --user=$u_db --password=$p_db -B -se "$sql_ban_perm")

					if test -z "$result_bp"
					then
						# Test sur le nombre de mots (resultat)
						if [ $nb -eq 2 ]	# Si 2 mots : le mot de passe est manquant
						then
							# On incrémente de 1 dans la table des bans temp // NO PASSWORD
							sql_add_temp="connect gammu; INSERT INTO $sms_t(SenderNumber) VALUES ('$numero');"
							mysql --user=$u_db --password=$p_db -B -se "$sql_add_temp"

						elif [ $nb -eq 3 ]	# Si 3 mots : id + mot de passe + numero 
						then
							export pass=$(echo $result | cut -d ' ' -f3)
							pass_salt=$(perl -e'print crypt($ARGV[0],$ARGV[1])' $pass $salt)
			
							export LC_TIME="en_US.UTF-8"
							expir=$(date '+%d %B %Y' -d "$time_account days")
			
							supp_acc_rad "$numero"
							add_acc_rad "$numero" "$pass_salt" "$expir"
							supp_num_temp "$numero"
							add_num_perm "$numero" "$expir"
						
						else	
						# Autrement, le mot de passe est trop grand ( > un mot )
							# On incrémente d'un 1 dans la table des bans temp
								sql_add_temp="connect gammu; INSERT INTO $sms_t(SenderNumber) VALUES ('$numero');"
								mysql --user=$u_db --password=$p_db -B -se "$sql_add_temp"
						fi
			
						# On gère les bans temp en ban perm
							sql_select_temp="connect gammu; SELECT ID FROM $sms_t WHERE SenderNumber='$numero'"
							r_select_temp=$(mysql --user=$u_db --password=$p_db -B -se "$sql_select_temp")
							nb_ban_t=$(echo $r_select_temp| wc -w)
			
						if [ $nb_ban_t -ge $nb_essais ]
						then
							supp_num_temp "$numero"
			
								export LC_TIME="en_US.UTF-8"
								expir_f=$(date '+%d %B %Y' -d "$time_ban days")
				
							# Ajout du numero table SMS_ban_perm, 1 : flood
								sql_add_ban_perm="connect gammu; INSERT INTO $sms_p (SenderNumber,Perm,Expiration) VALUES ('$numero',1,'$expir_f');"
								mysql --user=$u_db --password=$p_db -B -se "$sql_add_ban_perm"
						fi	
					else
						date_expiration=$(echo $result_bp | cut -d ' ' -f2,3,4)
						perm=$(echo $result_bp | cut -d ' ' -f5)
			
						export LC_TIME="en_US.UTF-8"
						date_script=$(date '+%d %B %Y' -d "now")

					# On converti les deux dates en secondes, pour les comparer.
						d_exp=$(date --date "$date_expiration" +%s)
						d_scr=$(date --date "$date_script" +%s)

						if test $d_scr -ge $d_exp		# Si le ban à expiré
						then

							# Test sur le nombre de mots (resultat)
							if [ $nb -eq 2 ]	# Si 2 mots : le mot de passe est manquant
							then
							# On incrémente de 1 dans la table des bans temp
								sql_add_temp="connect gammu; INSERT INTO $sms_t(SenderNumber) VALUES ('$numero');"
								mysql --user=$u_db --password=$p_db -B -se "$sql_add_temp"

							elif [ $nb -eq 3 ]	# Si 3 mots : id + mot de passe + numero 
							then
								date_expiration=$(echo $result_bp | cut -d ' ' -f2,3,4)
								perm=$(echo $result_bp | cut -d ' ' -f5)

								date_script=$(date '+%d %B %Y' -d "now")

							# On converti les deux dates en secondes, pour les comparer.
								d_exp=$(date --date "$date_expiration" +%s)
								d_scr=$(date --date "$date_script" +%s)

								export pass=$(echo $result | cut -d ' ' -f3)
								pass_salt=$(perl -e'print crypt($ARGV[0],$ARGV[1])' $pass $salt)
				
								export LC_TIME="en_US.UTF-8"
								expir=$(date '+%d %B %Y' -d "$time_account days")


								supp_acc_rad "$numero"
								add_acc_rad "$numero" "$pass_salt" "$expir"
								supp_num_temp "$numero"
								supp_num_perm "$numero"
								add_num_perm "$numero" "$expir"
					
							else	
							# Autrement, le mot de passe est trop grand ( > un mot )
								# On incrémente d'un 1 dans la table des bans temp
									sql_add_temp="connect gammu; INSERT INTO $sms_t(SenderNumber) VALUES ('$numero');"
									mysql --user=$u_db --password=$p_db -B -se "$sql_add_temp"
									echo "Mot de passe incorrect, ajout du numero en ban temporaire"
							fi
				
							# On gère les bans temp en ban perm
								sql_select_temp="connect gammu; SELECT ID FROM $sms_t WHERE SenderNumber='$numero'"
								r_select_temp=$(mysql --user=$u_db --password=$p_db -B -se "$sql_select_temp")
								nb_ban_t=$(echo $r_select_temp| wc -w)
			
							if [ $nb_ban_t -ge $nb_essais ]
							then
								supp_num_perm "$numero"
								supp_num_temp "$numero"
			
									export LC_TIME="en_US.UTF-8"
									expir_f=$(date '+%d %B %Y' -d "$time_ban days")
			
								# Ajout du numero table SMS_ban_perm, 1 : flood
									sql_add_ban_perm="connect gammu; INSERT INTO $sms_p (SenderNumber,Perm,Expiration) VALUES ('$numero',1,'$expir_f');"							mysql --user=$u_db --password=$p_db -B -se "$sql_add_ban_perm"
							fi
						else
							echo "Le ban de $numero est encore valide"	
						fi	
						break
					fi
				#else
					#echo "Pays bloqué"
				fi
			done
		else
			echo "Numero non autorisé (ex: 36665)"
		fi
				# On supprime la ligne d'ID=$id dans inbox
				mysql --user=$u_db --password=$p_db -B -e "$sql_delete_inbox WHERE ID=$id;"
		done
} # end function new_sms


# CORE
case $args in
	-h | --help)
		echo "$usage"
		exit 0
		;;
	--start)
		gammu_pid=`/usr/sbin/pidof gammu-smsd|wc -l`
		if [ $gammu_pid != "0" ]
			then
			echo "gammu is already started"
		else
			start_gammu
			sed -i "s/\$service_SMS_status=\"false\";/\$service_SMS_status=\"true\";/g" $index_page
			sed -i "s/\$service_SMS_status=false;/\$service_SMS_status=true;/g" $public_page
			sed -i "s/\$service_SMS_status=false;/\$service_SMS_status=true;/g" $intercept_page
		fi
		exit 0
		;;
	--stop)
		gammu_pid=`/usr/sbin/pidof gammu-smsd|wc -l`
		if [ $gammu_pid != "0" ]
			then
			stop_gammu
			sed -i "s/\$service_SMS_status=\"true\";/\$service_SMS_status=\"false\";/g" $index_page
			sed -i "s/\$service_SMS_status=true;/\$service_SMS_status=false;/g" $public_page
			sed -i "s/\$service_SMS_status=true;/\$service_SMS_status=false;/g" $intercept_page
		else
			echo "gammu is already stopped"
		fi
		exit 0 
		;;
	--pidof)
		/sbin/pidof gammu-smsd
		;;
	--last_nosim)
		# Récupère la dernière ligne où NOSIM est présent (error)
		cat $logfile | grep -n "NOSIM" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_start)
		# Récupère la dernière ligne où ########## est présent (séparateur)
		cat $logfile | grep -n "##########" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_stop)
		# Récupère la dernière ligne où %%%%%%%%%% est présent (séparateur)
		cat $logfile | grep -n "%%%%%%%%%%" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_writeerror)
		#Récupère la dernière ligne où SECURITYERROR est présent (error)
		cat $logfile | grep -n "DEVICEWRITEERROR" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_timeout)
		# Récupère la dernière ligne où SECURITYERROR est présent (error)
		cat $logfile | grep -n "TIMEOUT" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_secu)
		# Récupère la dernière ligne où SECURITYERROR est présent (error)
		cat $logfile | grep -n "SECURITYERROR" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	--last_puk)
		# Récupère la dernière ligne où PUK est présent (error)
		cat $logfile | grep -n "UNKNOWN" | cut -d ':' -f1 | tail -n 1
		exit 0 
		;;
	#--log)
	#	# Récupère le nom du fichier de log
	#	cat $config | grep logfile | cut -d ' ' -f3
	#	exit 0 
	#	;;
	--connect)
		# Récupère la vitesse de co
		cat $config | grep connection | cut -d ' ' -f3
		exit 0 
		;;
	--replace_connect)
		# Edition de la vitesse de co
		sed -i "s/^connection = at.*/connection = at$2/g" $config
		exit 0 
		;;
	--pin)
		# Récupère le code PIN (file de conf)
		cat $config | grep PIN | cut -d ' ' -f3
		exit 0 
		;;
	--replace_pin)
		# Edition du code PIN
		sed -i "s/^PIN =.*/PIN = $2/g" $config
		exit 0 
		;;
	--try_ban)
		# Récupère le nombre d'essais avant le ban perm
		grep nb_essais= $script | head -n 1 | cut -d '=' -f2
		exit 0 
		;;
	--replace_try_ban)
		# Edition le nombre d'essais avant le ban perm
		sed -i "s/^nb_essais=.*/nb_essais=$2/g" $script
		exit 0 
		;;
	--time_account)
		# Récupère la durée en jours de la session créée
		grep time_account= $script | head -n 1 | cut -d '=' -f2
		exit 0 
		;;
	--replace_time_account)
		# Edition de la durée de la session créée
		sed -i "s/^time_account=.*/time_account=$2/g" $script
		exit 0 
		;;
	--time_perm)
		# Récupère la durée un jours d'un ban perm (après flood par exemple)
		grep time_ban= $script | head -n 1 | cut -d '=' -f2
		exit 0 
		;;
	--replace_time_perm)
		# Edition de la durée d'un ban perm
		sed -i "s/^time_ban=.*/time_ban=$2/g" $script
		exit 0 
		;;
	--unlock_num)
		# Appel de la fonction unlock : deban un numero $2
		unlock "$2"
		exit 0 
		;;
	--change_country)
		# Permet de changer l'état de blocage d'un pays
		a=""
		for i in "$@"
		do 
			a=$(echo "$a $i")
		done
		a=$(echo $a | cut -d ' ' -f2-$#)
		change_country "$a"
		exit
		;;
	--change_country_ena_all)
		# Active l'ensemble des pays
		sql_change_country="connect gammu; UPDATE $SMS_c SET status=1"
		mysql --user=$u_db --password=$p_db -B -se "$sql_change_country"
		exit
		;;
	--change_country_dis_all)
		# Desactive l'ensemble des pays
		sql_change_country="connect gammu; UPDATE $SMS_c SET status=0"
		mysql --user=$u_db --password=$p_db -B -se "$sql_change_country"
		exit
		;;
	--change_country_filter)
		# Change la valeur du filtrage (FR, UE, all, perso)
		sql_change_country="connect gammu; UPDATE $SMS_c SET id='$2' WHERE name='FILTRAGE'"
		mysql --user=$u_db --password=$p_db -B -se "$sql_change_country"
		break
		;;
	--new_sms)
		# Appel de la fonction new_sms : filtrage du password, creation du compte et ban
		new_sms
		exit 0
		;;
	--imei_device)
		# Recuperation de l'imei du device
		sql_imei_phones="connect gammu; SELECT \`IMEI\` FROM phones;"
		mysql --user=$u_db --password=$p_db -B -se "$sql_imei_phones"
		exit 0
		;;
	--signal_device)
		# Recuperation du signal du device
		sql_signal_phones="connect gammu; SELECT \`Signal\` FROM phones;"
		mysql --user=$u_db --password=$p_db -B -se "$sql_signal_phones"
		exit 0
		;;
	--sms_received)
		# Recuperation du nombre de sms reçu. Depuis la dernière activation.
		sql_sms_received="connect gammu; SELECT \`Received\` FROM phones;"
		mysql --user=$u_db --password=$p_db -B -se "$sql_sms_received"
		exit 0
		;;
	--numero_alcasar)
		# Récupère le numero de la clé 3g (téléphone)
		grep "\$current_num=" $public_page | head -n 1 | cut -d"'" -f2
		exit 0 
		;;
	--replace_numero_alcasar)
		# Edition du numero de la clé 3g (téléphone)
		sed -i "s/\$current_num=.*/\$current_num='$2';/g" $public_page
		exit 0 
		;;
	--mode)
		# Mode huawei
		mode_huawei
		exit 0
		;;
	*)
		# Default
		echo "$usage"
		exit 0
		;;
esac
exit 0
