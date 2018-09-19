#!/bin/bash
#export PATH=$PATH:/usr/lib/go-1.9/bin
#echo $PATH
#sudo -E /usr/lib/go/bin/gobgpd -f r3-go-config.conf
#sudo -E /usr/lib/go/bin/gobgp global rib -a ipv4 add 172.16.1.0/24

#r1 r1-eth0:r2-eth0 r1-eth1:r4-eth0

ifconfig r1-eth0 1.1.2.1 netmask 255.255.255.0
ifconfig r1-eth1 1.1.4.1 netmask 255.255.255.0
