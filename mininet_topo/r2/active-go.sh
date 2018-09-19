#!/bin/bash
export PATH=$PATH:/usr/lib/go-1.9/bin
#echo $PATH
sudo -E /usr/lib/go/bin/gobgpd -f r2-go-config.conf
