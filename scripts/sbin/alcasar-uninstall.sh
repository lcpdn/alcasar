#!/bin/bash
# $Id: alcasar-uninstall.sh 1675 2015-07-27 12:16:58Z richard $

# alcasar-uninstall.sh
# by Franck BOUIJOUX, Pascal LEVANT and Richard REY
# This script is distributed under the Gnu General Public License (GPL)

# Désisntallation d'ALCASAR
# Uninstall ALCASAR

SED="/bin/sed -i"
clear
echo "-----------------------------------------------------------------------------"
echo "**                     Uninstall/Update ALCASAR                            **"
echo "-----------------------------------------------------------------------------"
echo
# logout all logged users
/usr/local/sbin/alcasar-logout.sh all
# services_stop
echo "Stopping service : "
/usr/local/bin/alcasar-sms.sh --stop 
for i in alcasar-load_balancing havp freshclam ntpd dansguardian httpd radiusd mysqld dnsmasq dnsmasq-blacklist dnsmasq-whitelist dnsmasq-blackhole tinyproxy nfsen fail2ban iptables ulogd-ext-access ulogd-ssh ulogd-traceability vnstat
do
	[ -e /lib/systemd/system/$i.service ] && /usr/bin/systemctl disable $i.service && /usr/bin/systemctl stop $i.service 1>/dev/null && sleep 1
done
echo "Check the service clearing"
for i in alcasar-load_balancing havp freshclam ntpd dansguardian httpd radiusd mysqld dnsmasq dnsmasq-blacklist dnsmasq-whitelist dnsmasq-blackhole tinyproxy nfsen fail2ban iptables ulogd-ext-access ulogd-ssh ulogd-traceability vnstat
do
	if [ `systemctl is-active $i.service` == "active" ]
	then
		echo "The service '$i' need to be killed"
		/usr/bin/systemctl stop $i.service
		killall $i
	fi
done
echo "Reset ALCASAR main functions : "
#init
echo -en "\n- init(1) : "
# les fichiers situés dans /usr/local/ seront supprimés à la fin car encore utiles ici
rm -f /root/ALCASAR* && echo -n "1"
sleep 1

# gestion
echo -en "\n- gestion(10) : "
[ -d /var/www/html ] && rm -rf /var/www/html && echo -n "1, "
[ -e /etc/httpd/conf/httpd.conf.default ] && mv /etc/httpd/conf/httpd.conf.default /etc/httpd/conf/httpd.conf && echo -n "2, "
[ -e /etc/httpd/conf/modules.d/00_base.conf.default ] && mv /etc/httpd/conf/modules.d/00_base.conf.default /etc/httpd/conf/modules.d/00_base.conf && echo -n "3, "
[ -e /etc/php.ini.default ] && mv /etc/php.ini.default /etc/php.ini && echo -n "4, "
[ -e /etc/httpd/conf/vhosts-ssl.default ] && FIC_VIRTUAL_SSL=`find /etc/httpd/conf -type f -name *default_ssl_vhost.conf` && mv /etc/httpd/conf/vhosts-ssl.default $FIC_VIRTUAL_SSL && echo -n "5, "
if [ -d /usr/local/etc/digest ] # v >= 2.0
	then rm -rf /usr/local/etc/digest && echo -n "6, "
	else echo -n "6, "
fi
[ -e /etc/httpd/conf/webapps.d/alcasar.conf ] && rm -f /etc/httpd/conf/webapps.d/alcasar.conf && echo -n "7, "
[ -e /etc/httpd/conf/conf.d/ssl.conf.default ] && mv /etc/httpd/conf/conf.d/ssl.conf.default /etc/httpd/conf/conf.d/ssl.conf && echo -n "8, "
[ -e /usr/share/httpd/error/include/top.html.default ] && mv /usr/share/httpd/error/include/top.html.default /usr/share/httpd/error/include/top.html && echo -n "9, "
[ -e /usr/share/httpd/error/include/bottom.html.default ] && mv /usr/share/httpd/error/include/bottom.html.default /usr/share/httpd/error/include/top.html && echo -n "10"
sleep 1

# CA
echo -en "\n- AC(4) : "
[ -e /etc/pki/CA/alcasar-ca.crt ] && rm -f /etc/pki/CA/alcasar-ca.crt && echo -n "1, "
[ -e /etc/pki/CA/private/alcasar-ca.key ] && rm -f /etc/pki/CA/private/alcasar-ca.key && echo -n "2, "
[ -e /etc/pki/tls/certs/alcasar.crt ] && rm -f /etc/pki/tls/certs/alcasar.crt && echo -n "3, "
[ -e /etc/pki/tls/private/alcasar.key ] && rm -f /etc/pki/tls/private/alcasar.key && echo -n "4"
sleep 1

#init_db
echo -en "\n- init_db(2) : "
[ -e /etc/my.cnf.default ] && mv -f /etc/my.cnf.default /etc/my.cnf && echo -n "1, "
[ -e /lib/systemd/system/mysqld.service.default ] && mv -f /lib/systemd/system/mysqld.service.default /lib/systemd/system/mysqld.service && echo -n "2"
/usr/bin/systemctl daemon-reload
rm -rf /var/lib/mysql
sleep 1

#param_radius
echo -en "\n- radius(9) : "
[ -e /etc/raddb/radiusd-db-vierge.sql ] && rm -f /etc/raddb/radiusd-db-vierge.sql && echo -n "1, "
[ -e /etc/raddb/radiusd.conf.default ] && mv /etc/raddb/radiusd.conf.default /etc/raddb/radiusd.conf && echo -n "2, "
[ -e /etc/raddb/sites-enabled/alcasar ] && rm /etc/raddb/sites-enabled/alcasar && echo -n "3, "
[ -e /etc/raddb/sites-available/alcasar ] && rm /etc/raddb/sites-available/alcasar && echo -n "4, "
[ -e /etc/raddb/clients.conf.default ] && mv /etc/raddb/clients.conf.default /etc/raddb/clients.conf && echo -n "5, "
[ -e /etc/raddb/sql.conf.default ] && mv /etc/raddb/sql.conf.default /etc/raddb/sql.conf && echo -n "6, "
[ -e /etc/raddb/sql/mysql/dialup.conf.default ] && mv /etc/raddb/sql/mysql/dialup.conf.default /etc/raddb/sql/mysql/dialup.conf && echo -n "7, "
[ -e /etc/raddb/sql/mysql/counter.conf.default ] && mv /etc/raddb/sql/mysql/counter.conf.default /etc/raddb/sql/mysql/counter.conf && echo -n "8, "
[ -e /lib/systemd/system/radiusd.service.default ] && mv /lib/systemd/system/radiusd.service.default /lib/systemd/system/radiusd.service && echo -n "9"
sleep 1

#param_web_radius
echo -en "\n- web_radius(4) : "
[ -e /etc/freeradius-web/admin.conf.default ] && mv /etc/freeradius-web/admin.conf.default /etc/freeradius-web/admin.conf && echo -n "1, "
[ -e /etc/freeradius-web/naslist.conf ] && rm /etc/freeradius-web/naslist.conf && echo -n "2, "
[ -e /etc/freeradius-web/user_edit.attrs.default ] && mv /etc/freeradius-web/user_edit.attrs.default /etc/freeradius-web/user_edit.attrs && echo -n "3, "
[ -e /etc/freeradius-web/sql.attrmap.default ] || mv /etc/freeradius-web/sql.attrmap.default /etc/freeradius-web/sql.attrmap && echo -n "4"
sleep 1

#param_chilli
echo -en "\n- chilli(4) : "
[ -e /etc/init.d/chilli.default ] && mv /etc/init.d/chilli.default /etc/init.d/chilli && echo -n "1, "
[ -e /usr/libexec/chilli ] && rm /usr/libexec/chilli && echo -n "2, "
[ -e /etc/chilli.conf.default ] && mv /etc/chilli.conf.default /etc/chilli.conf && echo -n "3, "
[ -e /lib/systemd/system/chilli.service ] && rm /lib/systemd/system/chilli.service && echo -n "4"
sleep 1

#param_dansguardian
echo -en "\n- dansguardian(8) : "
[ -d /var/dansguardian ] && rm -rf /var/dansguardian && echo -n "1, "
[ -e /etc/dansguardian/dansguardian.conf.default ] && mv /etc/dansguardian/dansguardian.conf.default /etc/dansguardian/dansguardian.conf && echo -n "2, "
[ -e /etc/dansguardian/lists/bannedphraselist.default ] && mv /etc/dansguardian/lists/bannedphraselist.default /etc/dansguardian/lists/bannedphraselist && echo -n "3, "
[ -e /etc/dansguardian/dansguardianf1.conf.default ] && mv /etc/dansguardian/dansguardianf1.conf.default /etc/dansguardian/dansguardianf1.conf && echo -n "4, "
[ -e /etc/dansguardian/lists/bannedextensionlist.default ] && mv /etc/dansguardian/lists/bannedextensionlist.default /etc/dansguardian/lists/bannedextensionlist && echo -n "5, "
[ -e /etc/dansguardian/lists/bannedmimetypelist.default ] && mv /etc/dansguardian/lists/bannedmimetypelist.default /etc/dansguardian/lists/bannedmimetypelist && echo -n "6, "
[ -e /etc/dansguardian/lists/exceptioniplist.default ] && mv /etc/dansguardian/lists/exceptioniplist.default /etc/dansguardian/lists/exceptioniplist && echo -n "7, "
[ -e /etc/dansguardian/lists/bannedsitelist.default ] && mv /etc/dansguardian/lists/bannedsitelist.default /etc/dansguardian/lists/bannedsitelist && echo -n "8"
sleep 1

#antivirus
echo -en "\n- antivirus(5) : "
if [ -e /etc/init.d/havp ] 
	then
	[ -e /etc/havp/havp.config.default ] && mv /etc/havp/havp.config.default /etc/havp/havp.config && echo -n "1, "
	userdel -r havp 2>/dev/null && echo -n "2, "
	[ `grep havp /etc/fstab|wc -l` -ne "0" ] && $SED "/havp/d" /etc/fstab # anciennes versions (mémoire tampon sur disque)
	[ -e /etc/init.d/havp.default ] && mv /etc/init.d/havp.default /etc/init.d/havp && echo -n "3, "
	[ -e /lib/systemd/system/havp.service.default ] && mv /lib/systemd/system/havp.service.default /lib/systemd/system/havp.service && echo -n "4, "
	[ -e /etc/freshclam.conf.default ] && mv /etc/freshclam.conf.default /etc/freshclam.conf && echo -n "5"
else	echo -n "uninstalled"
fi
sleep 1

#tinyproxy
echo -en "\n- tinyproxy(2) : "
if [ -e /etc/init.d/tinyproxy ] 
	then
	[ -e /etc/tinyproxy/tinyproxy.conf.default ] && mv /etc/tinyproxy/tinyproxy.conf.default /etc/tinyproxy/tinyproxy.conf && echo -n "1, "
	userdel -r tinyproxy 2>/dev/null && echo -n "2"
else	echo -n "uninstalled"
fi
sleep 1

#param_ulogd
echo -en "\n- ulogd(6) : "
i=0
for log_type in traceability ssh ext-access
      do
      i=`expr $i + 1`
      [ -e /etc/ulogd-$log_type.conf ] && rm -f /etc/ulogd-$log_type.conf && echo -n "$i, "
      i=`expr $i + 1`
      [ -e /lib/systemd/system/ulogd-$log_type.service ] && rm -f /lib/systemd/system/ulogd-$log_type.service && echo -n "$i, "
      done
sleep 1

#nfsen
echo -en "\n- nfsen(1) : "
[ -e /lib/systemd/system/nfsen.service ] && rm -f /lib/systemd/system/nfsen.service && echo -n "1"
sleep 1

#vnstat
echo -en "\n- vnstat(1) : "
[ -e /etc/vnstat.conf.default ] && mv /etc/vnstat.conf.default /etc/vnstat.conf && echo -n "1"
sleep 1

#DnsMasq
echo -en "\n- dnsmasq(9) : "
if [ -e /lib/systemd/system/dnsmasq.service ]
then
	[ -e /etc/sysconfig/dnsmasq.default ] && mv /etc/sysconfig/dnsmasq.default /etc/sysconfig/dnsmasq && echo -n "1, "
	[ -e /etc/dnsmasq.conf.default ] && mv /etc/dnsmasq.conf.default /etc/dnsmasq.conf && echo -n "2, "
	[ -e /lib/systemd/system/dnsmasq.service.default ] && mv /lib/systemd/system/dnsmasq.service.default /lib/systemd/system/dnsmasq.service && echo -n "3, "
	i=3
	for list in blacklist whitelist blackhole
	do
		i=`expr $i + 1`
		[ -e /etc/dnsmasq-$list.conf ] && rm /etc/dnsmasq-$list.conf && echo -n "$i, "
		i=`expr $i + 1`
		[ -e /lib/systemd/system/dnsmasq-$list.service ] && rm /lib/systemd/system/dnsmasq-$list.service && echo -n "$i, "
	done
else echo -n "uninstalled"
fi
sleep 1

#BL
echo -en "\n- BL(0) : "
sleep 1

#dhcpd
echo -en "\n- dhcp-server(1) : "
if [ -e /etc/init.d/dhcpd ]
then
	/usr/sbin/urpme --auto dhcp-server --auto-orphans && echo -n "1"
else echo -n "uninstalled"
fi
sleep 1

#fail2ban
echo -en "\n- fail2ban(8) : "
[ -e /etc/fail2ban/fail2ban.conf.default ] && mv /etc/fail2ban/fail2ban.conf.default /etc/fail2ban/fail2ban.conf && echo -n "1, "
[ -e /etc/fail2ban/jail.conf.default ] && mv /etc/fail2ban/jail.conf.default /etc/fail2ban/jail.conf && echo -n "2, "
[ -e /etc/fail2ban/action.d/iptables-allports.conf.default ] && mv /etc/fail2ban/action.d/iptables-allports.conf.default /etc/fail2ban/action.d/iptables-allports.conf && echo -n "3, "
[ -e /etc/fail2ban/filter.d/alcasar_mod-evasive.conf ] && rm /etc/fail2ban/filter.d/alcasar_mod-evasive.conf && echo -n "4, "
[ -e /etc/fail2ban/filter.d/alcasar_htdigest.conf ] && rm /etc/fail2ban/filter.d/alcasar_htdigest.conf && echo -n "5, "
[ -e /etc/fail2ban/filter.d/alcasar_intercept.conf ] && rm /etc/fail2ban/filter.d/alcasar_intercept.conf && echo -n "6, "
[ -e /etc/fail2ban/filter.d/alcasar_change-pwd.conf ] && rm /etc/fail2ban/filter.d/alcasar_change-pwd.conf && echo -n "7, "
[ -e /lib/systemd/system/fail2ban.service.default ] && mv /lib/systemd/system/fail2ban.service.default /lib/systemd/system/fail2ban.service && echo -n "8"
sleep 1

#cron
echo -en "\n- cron(9) : "
[ -e /etc/crontab.default ] && mv /etc/crontab.default /etc/crontab && echo -n "1, "
[ -e /etc/anacrontab.default ] && mv /etc/anacrontab.default /etc/anacrontab && echo -n "2, "
[ -e /etc/cron.d/alcasar-mysql ] && rm -f /etc/cron.d/alcasar-mysql && echo -n "3, "
[ -e /etc/cron.d/alcasar-archive ] && rm -f /etc/cron.d/alcasar-archive && echo -n "4, "
[ -e /etc/cron.d/alcasar-clean_import ] && rm -f /etc/cron.d/alcasar-clean_import && echo -n "5, "
[ -e /etc/cron.d/alcasar-distrib-updates ] && rm -f /etc/cron.d/alcasar-distrib-updates && echo -n "6, "
[ -e /etc/cron.d/freeradius-web ] && rm -f /etc/cron.d/freeradius-web && echo -n "7, "
[ -e /etc/cron.d/alcasar-watchdog ] && rm -f /etc/cron.d/alcasar-watchdog && echo -n "8, "
[ -e /etc/cron.d/alcasar-daemon-watchdog ] && rm -f /etc/cron.d/alcasar-daemon-watchdog && echo -n "9"

sleep 1

#gammu-smsd
echo -en "\n- gammu-smsd(3) : "
[ -e /etc/gammu_smsd_conf ] && rm -f /etc/gammu_smsd_conf && echo -n "1, "
[ -e /etc/udev/rules.d/66-huawei.rules ] && rm -f /etc/udev/rules.d/66-huawei.rules && echo -n "2, "
[ -e /var/log/gammu-smsd ] && rm -rf /var/log/gammu-smsd && echo -n "3"
sleep 1

#network
echo -en "\n- network(10) : "
hostname localhost
CONF_FILE="/usr/local/etc/alcasar.conf"
EXTIF=`grep ^EXTIF= $CONF_FILE|cut -d"=" -f2`		# EXTernal InterFace
INTIF=`grep ^INTIF= $CONF_FILE|cut -d"=" -f2`		# INTernal InterFace
i=0
for nic in $EXTIF $INTIF
	do
	i=`expr $i + 1`
	/sbin/ifdown $nic
	[ -e /etc/sysconfig/network-scripts/default-ifcfg-$nic ] && mv -f /etc/sysconfig/network-scripts/default-ifcfg-$nic /etc/sysconfig/network-scripts/ifcfg-$nic && echo -n "$i, "
	done
[ -e /etc/sysconfig/network.default ] && mv /etc/sysconfig/network.default /etc/sysconfig/network && echo -n "3, "
[ -e /etc/hosts.default ] && mv /etc/hosts.default /etc/hosts && echo -n "4, "
[ -e /etc/ntp.conf.default ] && mv /etc/ntp.conf.default /etc/ntp.conf && echo -n "5, "
[ -e /etc/hosts.allow.default ] && mv /etc/hosts.allow.default /etc/hosts.allow && echo -n "6, "
[ -e /etc/hosts.deny.default ] && mv /etc/hosts.deny.default /etc/hosts.deny && echo -n "7, "
[ -e /etc/modprobe.preload.default ] && mv /etc/modprobe.preload.default /etc/modprobe.preload && echo -n "8, "
[ -e /lib/systemd/system/iptables.service.default ] && mv /lib/systemd/system/iptables.service.default /lib/systemd/system/iptables.service && echo -n "9, "
[ -e /usr/libexec/iptables.init.default ] && mv /usr/libexec/iptables.init.default /usr/libexec/iptables.init && echo -n "10"

/sbin/ifup $EXTIF
sleep 1

#post_install
echo -en "\n- post_install(6) : "
[ -e /etc/mageia-release.default ] && mv /etc/mageia-release.default /etc/mageia-release && echo -n "1, "
[ -e /etc/ssh/alcasar-banner-ssh ] && rm -f /etc/ssh/alcasar-banner-ssh && echo -n "2, "
[ -e /etc/ssh/sshd_config.default ] && mv /etc/ssh/sshd_config.default /etc/ssh/sshd_config && echo -n "3, "
[ -e /etc/bashrc.default ] && mv /etc/bashrc.default /etc/bashrc && echo -n "4, "
[ -e /etc/sudoers.default ] && mv /etc/sudoers.default /etc/sudoers && echo -n "5, "
[ -e /lib/systemd/system/alcasar-load_balancing.service ] && rm -f /lib/systemd/system/alcasar-load_balancing.service && echo -n "6"
sleep 1



#nettoyage (on retire les services supprimés ou remplacés dans la nouvelle version)
echo -en "\n- cleaning() : "
for rm_fic in /usr/local/bin /usr/local/sbin /usr/local/etc
	do
	rm -rf $rm_fic/alcasar*
	done
echo

