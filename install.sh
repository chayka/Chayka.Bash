#!/usr/bin/env bash
#
# The only param that is passed here is mysql root password that would be populated as global var.
# If omitted, then won't be populated
#

chmod u+x chayka.sh
ln -s ./chayka.sh /usr/local/bin/chayka
ln -s ./etc/nginx/chayka/ /etc/nginx/chayka
if [ ! -z $1 ]; then
export MYSQL_ROOT_PASSWORD=$1
echo "export MYSQL_ROOT_PASSWORD=$1" >> ~/.bashrc
fi
echo "Chayka bash helper script is good to go now!"