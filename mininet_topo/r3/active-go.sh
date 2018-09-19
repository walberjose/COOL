#!/bin/bash
export PATH=$PATH:/usr/lib/go-1.9/bin
#echo $PATH
sudo -E /usr/lib/go/bin/gobgpd -f r3-go-config.conf
sudo -E /usr/lib/go/bin/gobgp global rib -a ipv4 add 172.16.1.0/24
