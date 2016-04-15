#!/bin/bash

le_path='/opt/letsencrypt'
exp_limit=30;

# if [ ! -f $config_file ]; then
#         echo "[ERROR] config file does not exist: $config_file"
#         exit 1;
# fi

nginx_site_config="/etc/nginx/sites-available/$1"

if [ ! -f ${nginx_site_config} ]; then
        echo "[ERROR] config file does not exist: $nginx_site_config"
        exit 1;
fi

domain=`grep -m 1 "^\s*server_name" ${nginx_site_config} | sed 's/\s\+server_name\s\+//' | sed 's/\(\s\+.*;\|;\)\s*$//'`
site_root=`grep -m 1 "^\s*root" ${nginx_site_config} | sed "s/^\s\+root\s\+//" | sed 's/\(\s\+.*;\|;\)\s*$//'`
cert_file="/etc/letsencrypt/live/$domain/fullchain.pem"

echo "domain: [$domain]"
echo "site_root: $site_root"
echo "cert_file: $cert_file"

#exit 0;

if [ ! -f ${cert_file} ]; then
	echo "[ERROR] certificate file not found for domain $domain."
fi

exp=$(date -d "`openssl x509 -in ${cert_file} -text -noout|grep "Not After"|cut -c 25-`" +%s)
datenow=$(date -d "now" +%s)
days_exp=$(echo \( ${exp} - ${datenow} \) / 86400 |bc)

echo "Checking expiration date for $domain..."

if [ "$days_exp" -gt "$exp_limit" ] ; then
	echo "The certificate is up to date, no need for renewal ($days_exp days left)."
	exit 0;
else
	echo "The certificate for $domain is about to expire soon. Starting webroot renewal script..."
        # $le_path/letsencrypt-auto certonly -a webroot --agree-tos --renew-by-default --config $config_file
	updateCommand="/opt/letsencrypt/letsencrypt-auto certonly -a webroot --agree-tos --renew-by-default --webroot-path=${site_root} -d ${domain}"
	nslookup www.${domain} && ${updateCommand} -d www.${domain} || ${updateCommand}
	echo "Reloading nginx"
	service nginx reload
	echo "Renewal process finished for domain $domain"
	exit 0;
fi