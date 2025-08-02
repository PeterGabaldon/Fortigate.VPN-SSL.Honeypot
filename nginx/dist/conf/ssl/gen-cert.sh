#! /bin/bash

/usr/bin/openssl req -subj '/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=FortiGate/CN=FGT61FTZ24061580/emailAddress=support@fortinet.com/' -nodes -x509 -sha512 -newkey rsa:8192 -keyout "nginx.key" -out "nginx.crt" -days 3650
