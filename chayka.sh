#!/bin/bash

SYNTAX=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka COMMAND

COMMAND:
	setup-server    used in non-docker environment installs required utils
	add-site 	add site: create nginx configs, create site folder, relaunch nginx
	enable-site 	enable available nginx site configuration
	disable-site 	disable available nginx site configuration
	add-ssl 	add ssl support to existing site
	remove-ssl 	remove ssl support from site
	get-composer 	install composer - php package manager 
	install-pma 	install phpMyAdmin
	install-wp 	add wordpress installation to the specified site
	install-wp-tests    add test suite to existing wp instance
	install-wpp 	install registered chayka wpp plugins from packagist.org to WP
	create-db 	create database with privileged user
	run-sql-script 	run sql script
	generate-ssl    generate self-signed ssl certificate

To get help on specific command run:
	chayka help COMMAND
    or
	chayka COMMAND --help
------------------------------------------------------------------------------------------
EOF
)

SYNTAX_OPTION_HTDOCS=$(cat <<EOF
	--htdocs 		folder to put site to, "/var/www" assumed by default
EOF
)
SYNTAX_OPTION_USER=$(cat <<EOF
	-u, --user 		create user if not exists, add site folder symlink to 
				user home folder
EOF
)
SYNTAX_OPTION_PASS=$(cat <<EOF
	-p, --pass 		will ask for user password, if omitted or left empty, 
				will generate one automatically
EOF
)
SYNTAX_OPTION_SSL_SELF_SIGNED=$(cat <<EOF
	--ssl-self-signed 	self-signed ssl certificate will be issued
EOF
)
SYNTAX_OPTION_SSL_EMAIL=$(cat <<EOF
	--ssl-email 	letsencrypt ssl certificate will be issued
EOF
)
SYNTAX_OPTION_SSL_PRIVATE_KEY=$(cat <<EOF
	--ssl-private-key 	private ssl key issued by authority, will be copied
				to [HTDOCS]/example.com/certs/example.com.key
EOF
)
SYNTAX_OPTION_SSL_CHAINED_CERTS=$(cat <<EOF
	--ssl-chained-certs 	chained ssl authority certificates, will be copied
				to [HTDOCS]/example.com/certs/example.com.crt
EOF
)
SYNTAX_OPTION_WORDPRESS=$(cat <<EOF
	--wp 		install latest wordpress
EOF
)
SYNTAX_OPTION_WORDPRESS_URL=$(cat <<EOF
	--wp-url 	install wordpress from specified zip location
EOF
)
SYNTAX_OPTION_WORDPRESS_ADMIN=$(cat <<EOF
	--wp-admin 	wordpress admin name, 'Admin' by default
EOF
)
SYNTAX_OPTION_WORDPRESS_EMAIL=$(cat <<EOF
	--wp-email 	wordpress admin email
EOF
)
SYNTAX_OPTION_WORDPRESS_PASS=$(cat <<EOF
	--wp-pass 	wordpress admin password
EOF
)
SYNTAX_OPTION_DB_HOST=$(cat <<EOF
	--db-host 		database host, 'localhost' by default
EOF
)
SYNTAX_OPTION_DB_PORT=$(cat <<EOF
	--db-port 		database port, '3306' by default
EOF
)
SYNTAX_OPTION_DB_NAME=$(cat <<EOF
	--db-name 		database name to create
EOF
)
SYNTAX_OPTION_DB_USER=$(cat <<EOF
	--db-user 		database user to create and give privileges onto 
				db-name, if omitted, db-name will be used by default
EOF
)
SYNTAX_OPTION_DB_PASS=$(cat <<EOF
	--db-pass 		db user password will be asked for db-user,
				if omitted or you respond with empty string, password will 
				be generated using pwgen and stored to .db-credentials
EOF
)
SYNTAX_OPTION_DB_ROOT_PASS=$(cat <<EOF
	--db-root-pass 		db root password will be asked, needed to create 
				databases and db users, MYSQL_ROOT_PASSWORD by default
EOF
)
SYNTAX_OPTION_NGINX_SITE_TPL=$(cat <<EOF
	--site-tpl-conf 	nginx site config template,
				'/etc/nginx/chayka/<scheme>.example.com.conf' by default
EOF
)
SYNTAX_OPTION_NGINX_SITES_AVAILABLE=$(cat <<EOF
	--sites-available 	nginx site-available folder where to put configs,
				'/etc/nginx/sites-available' by default
EOF
)

# show syntax
if [ $# -eq 0 ]; then
	echo "${SYNTAX}"
	exit 0
fi

# get command name 

COMMAND="$1"
shift

WP_URL='http://wordpress.org/latest.zip'
WP_ADMIN='Admin'
HTDOCS_DIR=/var/www
DB_ROOT_PASS=${MYSQL_ROOT_PASSWORD:=${MYSQL_ENV_MYSQL_ROOT_PASSWORD}}
DB_HOST='localhost'
if [ ! -z ${MYSQL_ENV_MYSQL_ROOT_PASSWORD} ]; then
	DB_HOST='mysql'
fi
DB_PORT='3306'
PMA_DIR=/usr/share/phpmyadmin


# Use > 1 to consume two arguments per pass in the loop (e.g. each
# argument has a corresponding value to go with it).
# Use > 0 to consume one or more arguments per pass in the loop (e.g.
# some arguments don't have a corresponding value to go with it such
# as in the --default example).
ALL_OPTIONS_READ=false
while [[ $# > 0 ]]
do
	key="$1"
	value="$2"
	case ${key} in
	    --htdocs)
	    HTDOCS_DIR="$value"
	    shift # past argument
	    ;;
	    -u|--user)
	    NEW_USER="$value"
	    shift # past argument
	    ;;
	    -p|--pass)
	    ASK_PASS=1
	    ;;
	    --ssl-self-signed)
	    SSL_SELF_SIGNED=true
	    ;;
	    --ssl-email)
	    SSL_EMAIL="$value"
	    shift # past argument
	    ;;
	    --ssl-private-key)
	    SSL_PRIVATE_KEY="$value"
	    shift # past argument
	    ;;
	    --ssl-chained-certs)
	    SSL_CHAINED_CERTS="$value"
	    shift # past argument
	    ;;
	    --wp)
	    WP_INSTALL=1
	    ;;
	    --wp-url)
	    WP_INSTALL=1
	    WP_URL="$value"
	    shift # past argument
	    ;;
	    --wp-admin)
	    WP_ADMIN="$value"
	    shift # past argument
	    ;;
	    --wp-email)
	    WP_EMAIL="$value"
	    shift # past argument
	    ;;
	    --wp-pass)
	    WP_PASS="$value"
	    shift # past argument
	    ;;
	    --db-host)
	    DB_HOST="$value"
	    shift # past argument
	    ;;
	    --db-port)
	    DB_PORT="$value"
	    shift # past argument
	    ;;
	    --db-name)
	    DB_NAME="$value"
	    shift # past argument
	    ;;
	    --db-user)
	    DB_USER="$value"
	    shift # past argument
	    ;;
	    --db-pass)
		echo -n DB User Password: 
		read -s DB_PASS
		echo
	    ;;
	    --db-root-pass)
		echo -n DB Root User Password: 
		read -s DB_ROOT_PASS
		echo
	    ;;
	 #    [A-z]*)
		# PARAM=$key
		# ALL_OPTIONS_READ=true
		# ;;
		*)
		PARAM=${key}
		break
	    ;;
	esac
	shift # past argument or value
done


#
# download $1 and save it to $2
#
download() {
    if [ `which curl` ]; then
        curl -s "$1" > "$2";
    elif [ `which wget` ]; then
        wget -nv -O "$2" "$1"
    fi
}

#
# sets up php environment on server
#
command_setup_server() {
    apt-get update && apt-get install -my \
        curl \
        wget \
        git \
        unzip \
        mc \
        bc \
        nano \
        mcrypt \
        nginx \
        mysql-client \
        php5 \
        php5-intl \
        php5-json \
        php5-curl \
        php5-fpm \
        php5-gd \
        php5-mysql \
        php5-mcrypt \
        php5-cli \
        pwgen

    # install letsencrypt to /opt/letsencrypt
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    sudo git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt

    # install srdb to /usr/local/lib/Search-Replace-DB
    git clone https://github.com/interconnectit/Search-Replace-DB.git /usr/local/lib/Search-Replace-DB
    sudo ln -sf /usr/local/lib/Search-Replace-DB/srdb.cli.php /usr/local/bin/srdb
}

#
# By default all sites are created in /var/www/
# This command creates a symlink to a site in user's home folder
#
# ln -s $HTDOCS_DIR/$site/htdocs /home/$user/www/$site
#
attach_site_to_user() {
	local user=$1
	local site=$2
	if [ -z ${user} ] || [ -z ${site} ];then
		exit 0
	fi
	if [ ${site} ]; then
		if [ ! -d "/home/$user/www" ]; then
			mkdir /home/${user}/www
		fi
		ln -s ${HTDOCS_DIR}/${site}/htdocs /home/${user}/www/${site}
	fi
}

#
# Create user and optionally attach site to user home folder
#
create_user() {
	local user=$1
	local site=$2
	if [ ! ${user} ];then
		exit 0
	fi
	# create user only if absent
	local user_exists=$(users | grep "\b$user\b")
	if [ ! ${user_exists} ]; then
		useradd ${user}

		# setting password
		if [ ${ASK_PASS} ]; then
			passwd ${user}
		else
			pass=$(pwgen -cn 16 1)
			echo ${pass} | passwd user --stdin
			cat ${pass} > /home/${user}/.pass
		fi
	fi
	if [ ${site} ]; then
		attach_site_to_user "$user" "$site"
	fi
}

#
# Perform a mysql db query
#
db_query() {
	local SQL=$1

	if [ ! -z $2 ]; then
		mysql --host "$DB_HOST" --port "$DB_PORT" --password="$DB_ROOT_PASS" -e "$2" "$1"
	else
		mysql --host "$DB_HOST" --port "$DB_PORT" --password="$DB_ROOT_PASS" -e "$SQL"
	fi

}

#
# Run sql script on mysql db
#
db_script() {
	local SQL=$1

	if [ ! -z $2 ]; then
		# SQL=$(cat $2)
		# SQL="USE $1; $SQL"
		mysql --host "$DB_HOST" --port "$DB_PORT" --password="$DB_ROOT_PASS" $1 < "$2"
	else
		mysql --host "$DB_HOST" --port "$DB_PORT" --password="$DB_ROOT_PASS" < "$SQL"
	fi

}

SYNTAX_COMMAND_GENERATE_SSL=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka generate-ssl DOMAIN

Examples:
	chayka generate-ssl example.com

------------------------------------------------------------------------------------------
EOF
)

#
# Generate SSL certificate for site
# TODO: Update it for Let's encrypt flow
#
command_generate_ssl() {
	local domain=$1
	if [ ! ${domain} ]; then
		echo "$SYNTAX_COMMAND_GENERATE_SSL"
		exit 0
	fi
	local dir="/var/www/$domain/certs"

	if [ ! -d ${dir} ]; then
		mkdir ${dir}
	fi

	cd ${dir}

	cp /etc/ssl/openssl.cnf ${dir}/${domain}.cnf

	echo '[ subject_alt_name ]' >> ${dir}/${domain}.cnf
	echo "subjectAltName = DNS:$domain, DNS:*.$domain" >> ${dir}/${domain}.cnf

	openssl genrsa -des3 -passout pass:x -out ${domain}.pass.key 2048
	openssl rsa -passin pass:x -in ${domain}.pass.key -out ${domain}.self.key
	rm ${domain}.pass.key
	openssl req -new -config ${domain}.cnf -key ${domain}.self.key -out ${domain}.self.csr \
		-subj "/OU=IT Department/CN=$domain"
	openssl x509 -req -days 365 -in ${domain}.self.csr -signkey ${domain}.self.key -out ${domain}.self.crt
}

SYNTAX_COMMAND_CREATE_DB=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka create-db [OPTIONS] DB_NAME

OPTIONS:
${SYNTAX_OPTION_DB_HOST}

${SYNTAX_OPTION_DB_PORT}

${SYNTAX_OPTION_DB_USER}

${SYNTAX_OPTION_DB_PASS}

${SYNTAX_OPTION_DB_ROOT_PASS}

Examples:
	chayka create-db example
	chayka create-db --db-user sampleuser --db-pass example

------------------------------------------------------------------------------------------
EOF
)

#
# Create database
#
command_create_db() {
	local db_name="$1"
	db_name=${db_name:-$DB_NAME}
	local db_user="$2"
	db_user=${db_user:-$DB_USER}
	db_user=${db_user:-$db_name}
	db_user=${db_user:0:16}
	local db_pass="$3"
	db_pass=${db_pass:-$(pwgen -cn 16 1)}
	if [ ! ${db_name} ]; then
		echo "$SYNTAX_COMMAND_CREATE_DB"
		exit 0
	fi

	db_query "CREATE DATABASE IF NOT EXISTS $db_name CHARACTER SET utf8 COLLATE utf8_general_ci"
	db_query "GRANT ALL PRIVILEGES ON $db_name.* TO '$db_user'@'%' IDENTIFIED BY '$db_pass'"

echo $(cat <<EOF
MySQL credentials:
	Host:		${DB_HOST}:${DB_PORT}
	Database:	${db_name}
	User:		${db_user}
	Password:	${db_pass}
EOF
)
}

SYNTAX_COMMAND_LETSENCRYPT=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka letsencrypt [--ssl-email EMAIL] DOMAIN

EOF
)

#
# Obtain letsencrypt certificate, setup auto-renewal
#
command_letsencrypt() {
    # installing prerequisites
    command -v bc || apt-get update && apt-get -y install bc

    local le_home="/opt/letsencrypt/"

    local domain="$1"
    local email=${SSL_EMAIL}

    if [ -z ${domain} ]; then
		echo "$SYNTAX_COMMAND_LETSENCRYPT"
		exit 0
    fi

    # install letsencrypt if needed
    if [ ! -e ${le_home} ]; then
        echo "Installing letsencrypt..."
        git clone https://github.com/letsencrypt/letsencrypt ${le_home}
    else
        echo "Updating letsencrypt..."
        cd ${le_home} && git pull
    fi

    # create a folder that webroot plugin will use
    if [ ! -e /var/www/${domain}/htdocs/.well-known/ ]; then
        mkdir /var/www/${domain}/htdocs/.well-known/
        chown www-data:www-data /var/www/${domain}/htdocs/.well-known/
    fi

    local leCommand=''

    if [ ! -e /etc/letsencrypt/live/${domain}/ ]; then
        # obtain certificate
        if [ -z ${email} ]; then
            echo "email not provided to obtain certificate"
    		exit 1
        fi
        leCommand="${le_home}letsencrypt-auto certonly --non-interactive --text --agree-tos --email ${email} --webroot --webroot-path /var/www/${domain}/htdocs -d ${domain}"
    else
        # update certificate
        leCommand="${le_home}letsencrypt-auto certonly --agree-tos --renew-by-default -a webroot --webroot-path=/var/www/${domain}/htdocs -d ${domain}"
    fi

    nslookup www.${domain} && ${leCommand} -d www.${domain} || ${leCommand}

    # create cron job if absent to update certificates that are expiring soon
    local cronfile="/etc/cron.d/letsencrypt.renew.$domain"
    if [ ! -e ${cronfile} ]; then
        echo "30 2 * * 1 letsencrypt-renew $domain >> /var/log/letsencrypt.renew.$domain.log 2>&1" > ${cronfile}
    fi
}

SYNTAX_COMMAND_ADD_SSL=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka add-ssl [--ssl-email EMAIL] DOMAIN

EOF
)

#
# Obtain letsencrypt certificate, setup auto-renewal
#
command_add_ssl() {
    local domain="$1"
    local email=${SSL_EMAIL}

    if [ -z ${domain} ]; then
		echo "$SYNTAX_COMMAND_ADD_SSL"
		exit 0
    fi

    # create nginx config
    if [ ! -e /etc/nginx/sites-available/https.${domain} ]; then
        sed -e "s/example.com/$domain/g" -e "s|/var/www|$HTDOCS_DIR|" /etc/nginx/chayka/https.example.com.conf > /etc/nginx/sites-available/https.${domain}
    fi

    command_letsencrypt ${domain}

    rm /etc/nginx/sites-enabled/${domain}
    ln -s /etc/nginx/sites-available/https.${domain} /etc/nginx/sites-enabled/${domain}

	nginx -t && nginx -s reload
}

SYNTAX_COMMAND_ADD_SITE=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka add-site [OPTIONS] DOMAIN

OPTIONS:
${SYNTAX_OPTION_HTDOCS}

${SYNTAX_OPTION_USER}

${SYNTAX_OPTION_PASS}

${SYNTAX_OPTION_SSL_EMAIL}

${SYNTAX_OPTION_SSL_PRIVATE_KEY}

${SYNTAX_OPTION_SSL_CHAINED_CERTS}

${SYNTAX_OPTION_WORDPRESS}

${SYNTAX_OPTION_WORDPRESS_URL}

${SYNTAX_OPTION_WORDPRESS_ADMIN}

${SYNTAX_OPTION_WORDPRESS_EMAIL}

${SYNTAX_OPTION_WORDPRESS_PASS}

${SYNTAX_OPTION_DB_NAME}

${SYNTAX_OPTION_DB_USER}

${SYNTAX_OPTION_DB_PASS}

${SYNTAX_OPTION_DB_ROOT_PASS}

${SYNTAX_OPTION_NGINX_SITE_TPL}

${SYNTAX_OPTION_NGINX_SITES_AVAILABLE}

Examples:
	chayka add-site example.com
	chayka add-http --htdocs /var/www/ example.com

------------------------------------------------------------------------------------------
EOF
)

#
# Add site:
#   - create nginx config
#   - create site folder
#
command_add_site() {
	local domain=$1
	if [ -z ${domain} ]; then
		echo "$SYNTAX_COMMAND_ADD_SITE"
		exit 0
	fi
	# create directory if needed
	if [ ! -d "$HTDOCS_DIR/$domain" ]; then
		mkdir ${HTDOCS_DIR}/${domain}
		mkdir ${HTDOCS_DIR}/${domain}/logs
		mkdir ${HTDOCS_DIR}/${domain}/backup
		mkdir ${HTDOCS_DIR}/${domain}/certs
		mkdir ${HTDOCS_DIR}/${domain}/htdocs
		mkdir ${HTDOCS_DIR}/${domain}/nginx
		ln -s /usr/share/phpmyadmin ${HTDOCS_DIR}/${domain}/htdocs/phpmyadmin
	fi

	if [ ! -z ${NEW_USER} ]; then
		create_user "$NEW_USER" "$domain"
	fi

	# add entry to /etc/hosts in case dns is not working yet
	cat /etc/hosts | grep "\s$domain" || echo "127.0.0.1	$domain" >> /etc/hosts

	# check if everything is ready for ssl
	local scheme='http'

	if [ ${SSL_SELF_SIGNED} ]; then
		scheme='https'
	fi

	if [ ! -z ${SSL_PRIVATE_KEY} ] && [ ! -z ${SSL_CHAINED_CERTS} ]; then
		scheme='https'
		cp ${SSL_PRIVATE_KEY} ${HTDOCS_DIR}/${domain}/certs/${domain}.key
		cp ${SSL_CHAINED_CERTS} ${HTDOCS_DIR}/${domain}/certs/${domain}.crt
	fi

	# create nginx config
	sed -e "s/example.com/$domain/g" -e "s|/var/www|$HTDOCS_DIR|" /etc/nginx/chayka/${scheme}.example.com.conf > /etc/nginx/sites-available/${scheme}.${domain}

	if [ ${SSL_SELF_SIGNED} ]; then
	    command_generate_ssl ${domain}
    	sed -ri "s/\.key/.self.key/" /etc/nginx/sites-available/${scheme}.${domain}
    	sed -ri "s/\.crt/.self.crt/" /etc/nginx/sites-available/${scheme}.${domain}
	fi

	# enable nginx site
	if [ -e /etc/nginx/sites-enabled/${domain} ]; then
		rm /etc/nginx/sites-enabled/${domain}
	fi

	ln -s /etc/nginx/sites-available/${scheme}.${domain} /etc/nginx/sites-enabled/${domain}

	# test nginx config and reload
	nginx -t && nginx -s reload

	if [ ${SSL_EMAIL} ]; then
	    command_add_ssl ${domain}
	fi
}

#
# Uncomment PhpMyAdmin config options
#
pma_uncomment() {
	local key="$1"
	sed -ri "s/\/\/\s*\\\$cfg\['Servers'\]\[\\\$i\]\['$key'\]/\$cfg['Servers'][\$i]['$key']/" "$PMA_DIR/config.inc.php"
}

#
# Set PhpMyAdmin config options
#
pma_set_config() {
	local key="$1"
	local value="$2"
	sed -ri "s/\['$key']\s*=\s*'[^']*'/['$key'] = '$value'/" "$PMA_DIR/config.inc.php"
}

#
# Install PhpMyAdmin on server
#
command_install_pma() {

	if [ ! -d ${PMA_DIR} ]; then
		echo "Installing phpMyAdmin"
		if [ ! -e phpmyadmin.zip ]; then
			wget -O phpmyadmin.zip https://github.com/phpmyadmin/phpmyadmin/archive/STABLE.zip >> /dev/null
		fi
	  	unzip phpmyadmin.zip >> /dev/null && \
	  	rm phpmyadmin.zip && \
	  	mv phpmyadmin-STABLE ${PMA_DIR} && \
	  	cp "$PMA_DIR/config.sample.inc.php" "$PMA_DIR/config.inc.php"

	  	local pma_db_password="$(pwgen -cn 16 1)"

		pma_uncomment 'controlhost'
		pma_uncomment 'controlport'
		pma_uncomment 'controluser'
		pma_uncomment 'controlpass'

		pma_set_config 'blowfish_secret' $(pwgen -cn 16 1)
		pma_set_config 'host' "mysql"
		
		pma_set_config 'controlhost' "mysql"
		pma_set_config 'controlport' "3306"
		pma_set_config 'controluser' "pma"
		pma_set_config 'controlpass' "$pma_db_password"

		pma_uncomment 'pmadb'
		pma_uncomment 'bookmarktable'
		pma_uncomment 'relation'
		pma_uncomment 'table_info'
		pma_uncomment 'table_coords'
		pma_uncomment 'pdf_pages'
		pma_uncomment 'column_info'
		pma_uncomment 'history'
		pma_uncomment 'table_uiprefs'
		pma_uncomment 'tracking'
		pma_uncomment 'userconfig'
		pma_uncomment 'recent'
		pma_uncomment 'favorite'
		pma_uncomment 'users'
		pma_uncomment 'usergroups'
		pma_uncomment 'navigationhiding'
		pma_uncomment 'savedsearches'
		pma_uncomment 'central_columns'
		pma_uncomment 'designer_settings'
		pma_uncomment 'export_templates'

	#	chayka-create-pma-db "$pma_db_password"
		db_script /usr/share/phpmyadmin/sql/create_tables.sql
		db_query "GRANT SELECT, INSERT, UPDATE, DELETE ON phpmyadmin.* TO 'pma'@'mysql'  IDENTIFIED BY '$pma_db_password'"
		echo "Installation of phpMyAdmin complete"
	fi

}

#
# Generate db name based on domain name
#
wp_db_name() {
	local domain=$1
	php -r 'echo preg_replace("/[^\w\d_]+/", "_", basename($argv[1]));' "$domain"
}

#
# Escape values for wp-config.php
#
wp_escape_lhs() {
	echo "$@" | sed 's/[]\/$*.^|[]/\\&/g'
}

#
# Escape values for wp-config.php
#
wp_escape_rhs() {
	echo "$@" | sed 's/[\/&]/\\&/g'
}

#
# Escape values for wp-config.php
#
wp_escape() {
	php -r 'var_export((string) $argv[1]);' "$1"
}

#
# Set WP config options
#
wp_set_config() {
	key="$1"
	value="$2"
	regex="(['\"])$(wp_escape_lhs "$key")\2\s*,"
	if [ "${key:0:1}" = '$' ]; then
		regex="^(\s*)$(wp_escape_lhs "$key")\s*="
	fi
	sed -ri "s/($regex\s*)(['\"]).*\3/\1$(wp_escape_rhs "$(wp_escape "$value")")/" wp-config.php
}

SYNTAX_COMMAND_INSTALL_WP=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka install-wp [OPTIONS] DOMAIN [CHAYKA_WPP_1 ... CHAYKA_WPP_N]

OPTIONS:
${SYNTAX_OPTION_HTDOCS}

${SYNTAX_OPTION_WORDPRESS_URL}

${SYNTAX_OPTION_WORDPRESS_ADMIN}

${SYNTAX_OPTION_WORDPRESS_EMAIL}

${SYNTAX_OPTION_WORDPRESS_PASS}

${SYNTAX_OPTION_DB_NAME}

${SYNTAX_OPTION_DB_USER}

${SYNTAX_OPTION_DB_PASS}

${SYNTAX_OPTION_DB_ROOT_PASS}

${SYNTAX_OPTION_SSL_EMAIL}

Examples:
	chayka install-wp example.com
	chayka install-wp \\
	    --wp-url https://ru.wordpress.org/wordpress-4.3.1-ru_RU.zip \\
	    --wp-email admin@example.com \\
	    --wp-pass SecretPassw0rd \\
	    --ssl-email admin@example.com \\
	    example.com auth-wpp comments-wpp search-wpp

------------------------------------------------------------------------------------------
EOF
)

#
# Install WordPress
#
command_install_wp () {
	local domain=$1
	local db_pass=${DB_PASS:-$(pwgen -cn 16 1)}
	local db_name=${DB_NAME:-$(wp_db_name $domain)}
	local db_user=${DB_USER:-$db_name}
	db_user=${db_user:0:16}
	local db_host=${DB_HOST:-'localhost'}

    if [ -z ${domain} ]; then
        echo "$SYNTAX_COMMAND_INSTALL_WP"
        exit 0
    fi

	if [ ! -d /var/www/${domain} ]; then
		command_add_site ${domain}
	fi

	cd "/var/www/$domain/htdocs"

	# Wordpress
	wget ${WP_URL} -O wordpress.zip
	unzip wordpress.zip
	mv ./wordpress/* .
	rmdir ./wordpress

	chown -R www-data:www-data .

	command_create_db ${db_name} ${db_user} ${db_pass} >> ../.db-credentals

	cp ./wp-config-sample.php ./wp-config.php

	#wp_set_config 'DB_HOST' "$MYSQL_PORT_3306_TCP_ADDR"
	wp_set_config 'DB_HOST' "$db_host"
	wp_set_config 'DB_USER' "$db_user"
	wp_set_config 'DB_PASSWORD' "$db_pass"
	wp_set_config 'DB_NAME' "$db_name"

	local uniques=(
		AUTH_KEY
		SECURE_AUTH_KEY
		LOGGED_IN_KEY
		NONCE_KEY
		AUTH_SALT
		SECURE_AUTH_SALT
		LOGGED_IN_SALT
		NONCE_SALT
	)
	for unique in ${uniques}[@]; do
        # if not specified, let's generate a random value
        current_set="$(sed -rn "s/define\((([\'\"])$unique\2\s*,\s*)(['\"])(.*)\3\);/\4/p" wp-config.php)"
        if [ "$current_set" = 'put your unique phrase here' ]; then
            wp_set_config "$unique" "$(head -c1M /dev/urandom | sha1sum | cut -d' ' -f1)"
        fi
	done

    local scheme="http"

	if [ ${SSL_EMAIL} ]; then
	    scheme="https"
	fi

	if [ ! -z ${WP_EMAIL} ] && [ ! -z ${WP_PASS} ]; then
		curl --data-urlencode "weblog_title=$domain" \
			--data-urlencode "user_name=$WP_ADMIN" \
			--data-urlencode "admin_password=$WP_PASS" \
			--data-urlencode "admin_password2=$WP_PASS" \
			--data-urlencode "pass1-text=$WP_PASS" \
			--data-urlencode "admin_email=$WP_EMAIL" \
			--data-urlencode "blog_public=1" \
			--data-urlencode "Submit=Install+WordPress" \
			"$scheme://$domain/wp-admin/install.php?step=2" >> /dev/null
        echo "$scheme://$domain/wp-admin/install.php?step=2 called"
	fi

    shift

    if [ $# -gt 0 ]; then
		cd ./wp-content/plugins
		git clone https://github.com/chayka/Chayka.Core.wpp.git
		cd ./Chayka.Core.wpp
		composer install
		while [[ $# -gt 0 ]]
		do
			local plugin="$1"
			composer require "chayka/$plugin"
			shift
		done   

    fi
}

#
# fetch wp-config.php param
#
wp_get_config_param(){
    local wp_config=${1-./wp-config.php}
    local param=$2
    cat ${wp_config} | grep ${param} | sed "s/define('${param}',\s*'\([^']*\)');/\1/"
}

SYNTAX_COMMAND_INSTALL_WP_TESTS=$(cat <<EOF
------------------------------------------------------------------------------------------
No params found, expected syntax:
	chayka install-wp-tests DOMAIN

Examples:
	chayka install-wp-tests example.com

------------------------------------------------------------------------------------------
EOF
)

#
# Install WP test suite libs.
# Will reuse DB credentials from wp-config.php
# Warning: running tests may reset DB, so don't do it on production WP instance
#
command_install_wp_test_suite() {
	local domain=$1

    if [ -z ${domain} ]; then
        echo "$SYNTAX_COMMAND_INSTALL_WP_TESTS"
        exit 0
    fi

    local WP_DIR=/var/www/${domain}/htdocs/
    local WP_TESTS_DIR=${WP_DIR}wp-content/tests-lib/

    local DB_HOST=$(wp_get_config_param ${WP_DIR}wp-config.php DB_HOST | sed "s/[\r\n]*$//")
    local DB_NAME=$(wp_get_config_param ${WP_DIR}wp-config.php DB_NAME | sed "s/[\r\n]*$//")
    local DB_USER=$(wp_get_config_param ${WP_DIR}wp-config.php DB_USER | sed "s/[\r\n]*$//")
    local DB_PASS=$(wp_get_config_param ${WP_DIR}wp-config.php DB_PASSWORD | sed "s/[\r\n]*$//")
    local DB_PREFIX=$(cat ${WP_DIR}wp-config.php | grep table_prefix | sed "s/\$table_prefix\s*=\s*'\([^']*\)';/\1/" | sed "s/[\r\n]*$//")

	#
	# Acquiring actual WP version to get correct test suite
	#
    local WP_VERSION=$(cat ${WP_DIR}readme.html | grep Version | sed "s/^\s*<br\s*\/>\s*Version\s*//")
    local WP_TESTS_TAG="tags/$WP_VERSION"

    #
	# set up testing suite if it doesn't yet exist
	#
	if [ ! -d ${WP_TESTS_DIR} ]; then
	    #
		# set up testing suite
		#
		mkdir -p ${WP_TESTS_DIR}

		#
		# check out from svn repository wp testing suite
		#
		svn co --quiet https://develop.svn.wordpress.org/${WP_TESTS_TAG}/tests/phpunit/includes/ ${WP_TESTS_DIR}includes
	fi

    #
	# portable in-place argument for both GNU sed and Mac OSX sed
	#
    local sed_option='-i'
	if [ $(uname -s) == 'Darwin' ]; then
		sed_option='-i .bak'
	fi

    #
    # Creating alternative bootstrap, that does not flush database
    # and does not check for WordPress specific test groups
    #
	if [ ! -f ${WP_TESTS_DIR}includes/bootstrap.chayka.php ]; then
	    cp ${WP_TESTS_DIR}includes/bootstrap.php ${WP_TESTS_DIR}includes/bootstrap.chayka.php
		sed ${sed_option} "s:system://system:" ${WP_TESTS_DIR}includes/bootstrap.chayka.php
		sed ${sed_option} "s:_delete_all_posts://_delete_all_posts:" ${WP_TESTS_DIR}includes/bootstrap.chayka.php
		sed ${sed_option} "s:new WP_PHPUnit_Util_Getopt://new WP_PHPUnit_Util_Getopt:" ${WP_TESTS_DIR}includes/bootstrap.chayka.php
    fi

    #
    # Creating alternative install.php script that drops all the tables and uses wp-tests-config.php
    #
	if [ ! -f ${WP_TESTS_DIR}includes/install.chayka.php ]; then
	    cp ${WP_TESTS_DIR}includes/install.php ${WP_TESTS_DIR}includes/install.chayka.php
		sed ${sed_option} 's:$wpdb->tables():$wpdb->get_col("SHOW TABLES"):' ${WP_TESTS_DIR}includes/install.chayka.php
		sed ${sed_option} 's:$argv\[1\]:dirname( __FILE__ ) . "/../wp-tests-config.php":' ${WP_TESTS_DIR}includes/install.chayka.php
		sed ${sed_option} 's:$argv\[2\]:$argv[1]:' ${WP_TESTS_DIR}includes/install.chayka.php
    fi

    #
    # setup wp-tests-config.php with db credentials
    #
	if [ ! -f wp-tests-config.php ]; then
		download https://develop.svn.wordpress.org/${WP_TESTS_TAG}/wp-tests-config-sample.php ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:dirname( __FILE__ ) . '/src/':'${WP_DIR}':" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:youremptytestdbnamehere:${DB_NAME}:" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:yourusernamehere:${DB_USER}:" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:yourpasswordhere:${DB_PASS}:" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:localhost:${DB_HOST}:" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:wptests_:${DB_PREFIX}:" ${WP_TESTS_DIR}wp-tests-config.php
		sed ${sed_option} "s:example.org:${domain}:" ${WP_TESTS_DIR}wp-tests-config.php
	fi
}

#
# Enable cache that is disabled by default
# More info: https://www.digitalocean.com/community/tutorials/how-to-add-swap-on-ubuntu-14-04
#
command_enable_swap() {
    local size='1G'
    local swappiness=10
    local pressure=50

    # swap file
    sudo fallocate -l ${size} /swapfile
    sudo chmod 600 /swapfile
    ls -lh /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    sudo swapon -s
    free -m
    echo "/swapfile   none    swap    sw    0   0" >> /etc/fstab

    # swappiness
    sudo sysctl vm.swappiness=${swappiness}
    echo "vm.swappiness=${swappiness}" >> /etc/sysctl.conf

    # cache pressure
    sudo sysctl vm.vfs_cache_pressure=${pressure}
    echo "vm.vfs_cache_pressure=${pressure}" >> /etc/sysctl.conf
}

#
# Launch requested command
#
case ${COMMAND} in
    setup-server)
        command_setup_server
    ;;
    add-site)
		command_add_site ${PARAM}
    ;;
    enable-site)
    ;;
    disable-site)
    ;;
    add-ssl)
        command_add_ssl ${PARAM}
    ;;
    remove-ssl)
    ;;
    get-composer)
		curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    ;;
    install-pma)
		command_install_pma
    ;;
    install-wp)
		command_install_wp $@
    ;;
    install-wp-tests)
		command_install_wp_test_suite ${PARAM}
    ;;
    install-wpp)
    ;;
    create-db)
		command_create_db ${PARAM}
    ;;
    run-sql-script)
    ;;
    generate-ssl)
		command_generate_ssl ${PARAM}
	;;
    letsencrypt)
		command_letsencrypt ${PARAM}
	;;
    *)
    ;;
esac
