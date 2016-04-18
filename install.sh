#!/usr/bin/env bash
#
# The only param that is passed here is mysql root password that would be populated as global var.
# If omitted, then won't be populated
#

#
# Acquiring current directory
#
cwd=$(pwd)

#
# Adding link to main script
#
if [ ! -e /usr/local/bin/chayka ]; then
    ln -s ${cwd}/chayka.sh /usr/local/bin/chayka
fi

#
# Adding link to nginx configs
#
if [ ! -e /etc/nginx/chayka ]; then
    ln -s ${cwd}/etc/nginx/chayka/ /etc/nginx/chayka
fi

#
# Adding link to letsencrypt-renew
#
if [ ! -e /usr/local/bin/letsecrypt-renew ]; then
    ln -s ${cwd}/letsecrypt-renew.sh /usr/local/bin/letsecrypt-renew
fi

#
# Populating CHAYKA_BASH_HOME env variable
#
if [ -z ${CHAYKA_BASH_HOME} ]; then
    export CHAYKA_BASH_HOME=${cwd}
    echo "export CHAYKA_BASH_HOME=$cwd" >> ~/.bashrc
fi

#
# Populating MYSQL_ROOT_PASSWORD env variable
#
if [ ! -z $1 ]; then
    export MYSQL_ROOT_PASSWORD=$1
    echo "export MYSQL_ROOT_PASSWORD=$1" >> ~/.bashrc
fi



echo "Chayka bash helper script is good to go now!"
echo "run 'chayka setup-server' if you haven't yet."