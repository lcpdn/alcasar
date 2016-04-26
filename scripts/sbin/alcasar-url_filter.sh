#/bin/bash

# alcasar-url_filter.sh
# by REXY
# This script is distributed under the Gnu General Public License (GPL)

# Active / désactive : safesearch des moteurs de recherche ainsi que le filtrage Youtube
# Enable / disable : search engines safesearch and Youtube filtering 
# Active / désactive : le filtrage des url contenant une adresse ip à la place d'un nom de domaine
# Enable / disable : filter of urls containing ip address instead of domain name 

DIR_DG="/etc/dansguardian/lists"
DNSMASQ_BL_CONF="/etc/dnsmasq-blacklist.conf"
CONF_FILE="/usr/local/etc/alcasar.conf"
SED="/bin/sed -i"
safesearch="Off"
pureip="Off"
usage="Usage: alcasar-url_filter.sh { -safesearch_on or -safesearch_off } & { -pureip_on or --pureip_off }"
nb_args=$#
if [ $nb_args -le 1 ]
then
	echo "$usage"
	nb_args=0
else
	while [ $nb_args -ge 1 ]
	do
		arg=${!nb_args}
		case $arg in
		-\? | -h* | --h*)
			echo "$usage"
			exit 0
			;;
		# Safe search activation
		-safesearch_on | --safesearch_on)	
			safesearch="On"
			;;
		# Safe search desactivation
		-safesearch_off | --safesearch_off)	
			safesearch="Off"
			;;
		# pure_ip activation
		-pureip_on | --pureip_on)
			pureip="On"
			;;
		# pureip desactivation
		-pureip_off | --pureip_off)
			pureip="Off"
			;;
		*)
			echo "Argument inconnu :$arg";
			echo "$usage"
			exit 1
			;;
		esac
	nb_args=$(expr $nb_args - 1)
	done
	if [ $safesearch == "On" ]
	then
		$SED "s?^#\"?\"?g" $DIR_DG/urlregexplist # on décommente les lignes de regles
		youtube_id=`grep YOUTUBE_ID $CONF_FILE|cut -d"=" -f2`
		$SED "s?\&edufilter=.*?\&edufilter=$youtube_id\"?g" $DIR_DG/urlregexplist
# add 'nosslsearch' redirection for google searching
#		$SED "/google/d" $DNSMASQ_BL_CONF # remove old google declaration
#		nossl_server=`host -ta nosslsearch.google.com|cut -d" " -f4`	# retrieve google nosslsearch ip
#		echo "# nosslsearch redirect server for google" >> $DNSMASQ_BL_CONF
#		for gg_dnsname in .google.com .google.ad .google.ae .google.com.af .google.com.ag .google.com.ai .google.al .google.am .google.co.ao .google.com.ar .google.as .google.at .google.com.au .google.az .google.ba .google.com.bd .google.be .google.bf .google.bg .google.com.bh .google.bi .google.bj .google.com.bn .google.com.bo .google.com.br .google.bs .google.bt .google.co.bw .google.by .google.com.bz .google.ca .google.cd .google.cf .google.cg .google.ch .google.ci .google.co.ck .google.cl .google.cm .google.cn .google.com.co .google.co.cr .google.com.cu .google.cv .google.com.cy .google.cz .google.de .google.dj .google.dk .google.dm .google.com.do .google.dz .google.com.ec .google.ee .google.com.eg .google.es .google.com.et .google.fi .google.com.fj .google.fm .google.fr .google.ga .google.ge .google.gg .google.com.gh .google.com.gi .google.gl .google.gm .google.gp .google.gr .google.com.gt .google.gy .google.com.hk .google.hn .google.hr .google.ht .google.hu .google.co.id .google.ie .google.co.il .google.im .google.co.in .google.iq .google.is .google.it .google.je .google.com.jm .google.jo .google.co.jp .google.co.ke .google.com.kh .google.ki .google.kg .google.co.kr .google.com.kw .google.kz .google.la .google.com.lb .google.li .google.lk .google.co.ls .google.lt .google.lu .google.lv .google.com.ly .google.co.ma .google.md .google.me .google.mg .google.mk .google.ml .google.com.mm .google.mn .google.ms .google.com.mt .google.mu .google.mv .google.mw .google.com.mx .google.com.my .google.co.mz .google.com.na .google.com.nf .google.com.ng .google.com.ni .google.ne .google.nl .google.no .google.com.np .google.nr .google.nu .google.co.nz .google.com.om .google.com.pa .google.com.pe .google.com.pg .google.com.ph .google.com.pk .google.pl .google.pn .google.com.pr .google.ps .google.pt .google.com.py .google.com.qa .google.ro .google.ru .google.rw .google.com.sa .google.com.sb .google.sc .google.se .google.com.sg .google.sh .google.si .google.sk .google.com.sl .google.sn .google.so .google.sm .google.sr .google.st .google.com.sv .google.td .google.tg .google.co.th .google.com.tj .google.tk .google.tl .google.tm .google.tn .google.to .google.com.tr .google.tt .google.com.tw .google.co.tz .google.com.ua .google.co.ug .google.co.uk .google.com.uy .google.co.uz .google.com.vc .google.co.ve .google.vg .google.co.vi .google.com.vn .google.vu .google.ws .google.rs .google.co.za .google.co.zm .google.co.zw .google.cat 
#		do
#			echo "address=/$gg_dnsname/$nossl_server" >> $DNSMASQ_BL_CONF
#		done
# add 'SafeSearch' redirection for google searching
		$SED "/google/d" $DNSMASQ_BL_CONF # remove old google declaration
		forcesafesearch_server=`host -ta forcesafesearch.google.com|cut -d" " -f4`	# retrieve google forcesafesearch ip
		echo "# SafeSearch redirect server for google" >> $DNSMASQ_BL_CONF
		for gg_dnsname in .google.com .google.ad .google.ae .google.com.af .google.com.ag .google.com.ai .google.al .google.am .google.co.ao .google.com.ar .google.as .google.at .google.com.au .google.az .google.ba .google.com.bd .google.be .google.bf .google.bg .google.com.bh .google.bi .google.bj .google.com.bn .google.com.bo .google.com.br .google.bs .google.bt .google.co.bw .google.by .google.com.bz .google.ca .google.cd .google.cf .google.cg .google.ch .google.ci .google.co.ck .google.cl .google.cm .google.cn .google.com.co .google.co.cr .google.com.cu .google.cv .google.com.cy .google.cz .google.de .google.dj .google.dk .google.dm .google.com.do .google.dz .google.com.ec .google.ee .google.com.eg .google.es .google.com.et .google.fi .google.com.fj .google.fm .google.fr .google.ga .google.ge .google.gg .google.com.gh .google.com.gi .google.gl .google.gm .google.gp .google.gr .google.com.gt .google.gy .google.com.hk .google.hn .google.hr .google.ht .google.hu .google.co.id .google.ie .google.co.il .google.im .google.co.in .google.iq .google.is .google.it .google.je .google.com.jm .google.jo .google.co.jp .google.co.ke .google.com.kh .google.ki .google.kg .google.co.kr .google.com.kw .google.kz .google.la .google.com.lb .google.li .google.lk .google.co.ls .google.lt .google.lu .google.lv .google.com.ly .google.co.ma .google.md .google.me .google.mg .google.mk .google.ml .google.com.mm .google.mn .google.ms .google.com.mt .google.mu .google.mv .google.mw .google.com.mx .google.com.my .google.co.mz .google.com.na .google.com.nf .google.com.ng .google.com.ni .google.ne .google.nl .google.no .google.com.np .google.nr .google.nu .google.co.nz .google.com.om .google.com.pa .google.com.pe .google.com.pg .google.com.ph .google.com.pk .google.pl .google.pn .google.com.pr .google.ps .google.pt .google.com.py .google.com.qa .google.ro .google.ru .google.rw .google.com.sa .google.com.sb .google.sc .google.se .google.com.sg .google.sh .google.si .google.sk .google.com.sl .google.sn .google.so .google.sm .google.sr .google.st .google.com.sv .google.td .google.tg .google.co.th .google.com.tj .google.tk .google.tl .google.tm .google.tn .google.to .google.com.tr .google.tt .google.com.tw .google.co.tz .google.com.ua .google.co.ug .google.co.uk .google.com.uy .google.co.uz .google.com.vc .google.co.ve .google.vg .google.co.vi .google.com.vn .google.vu .google.ws .google.rs .google.co.za .google.co.zm .google.co.zw .google.cat 
		do
			echo "address=/$gg_dnsname/$forcesafesearch_server" >> $DNSMASQ_BL_CONF
		done
	else
		$SED "s?^[^#]?#&?g" $DIR_DG/urlregexplist
		$SED "/google/d" $DNSMASQ_BL_CONF
	fi
	if [ $pureip == "On" ]
	then
		$SED "s/^\#\*ip$/*ip/g" $DIR_DG/bannedsitelist
	else
		$SED "s/^\*ip$/#*ip/g" $DIR_DG/bannedsitelist
	fi
systemctl restart dansguardian
systemctl restart dnsmasq-blacklist
fi

