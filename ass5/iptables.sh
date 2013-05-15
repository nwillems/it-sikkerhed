#!/bin/bash
#BIOmedix' new firewall
# Authors: Jens Fredskov, Nicolai Willems

#IP-addresses
fw_eth1="10.10.1.1"
fw_eth0="10.10.2.1"
workstation_net="10.10.1.0/24"
server_net="10.10.2.0/24"
inet="0/0"

##Internal servers
internal_dns="10.10.2.5"
internal_ftp="10.10.2.33"
internal_intra="10.10.2.7"
internal_admin="10.10.2.10"

##External servers
external_mail="130.255.254.17"
external_dns="130.255.254.10"
external_cvs="130.255.254.22"
external_web="130.255.254.11"
external_cluster="130.255.254.12"

# INITIALIZE
iptables --flush

#Default policies
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT


#Specific rules
## 1.2.1 DNS lookup
iptables -A FORWARD -s $workstation_net -d $internal_dns -p udp,tcp -m state \
    --state NEW,ESTABLISHED --sport 1024: --dport 53 -j ACCEPT
iptables -A FORWARD -s $internal_dns -d $workstation_net -p udp,tcp -m state \
    --state ESTABLISHED --dport 53 -j ACCEPT

## 1.2.2 HTTP & HTTPS 
iptables -A FORWARD -s $workstation_net -d $internal_intra,$inet -p tcp -m state \
    --state NEW,ESTABLISHED -sport 1024: -dport 80,443 -j ACCEPT
iptables -A FORWARD -s $internal_intra,$inet -d $workstation_net -p tcp -m state \
    --state ESTABLISHED --sport 80,443 --dport 1024: -j ACCEPT

## 1.2.3 Mail rules
### SMTP to external mail server - port 587 considered, but dropped(No MSA in
###     workstation net)
iptables -A FORWARD -s $workstation_net -d $external_mail -p tcp -m state \
    --state NEW,ESTABLISHED --sport 1024: --dport 25 -j ACCEPT
iptables -A FORWARD -s $external_mail -d $workstation_net -p tcp -m state \
    --state ESTABLISHED --sport 25 --dport 1024: -j ACCEPT

### SSL POP3
iptables -A FORWARD -s $workstation_net -d $external_mail -p tcp -m state \
    --state NEW,ESTABLISHED --sport 1024: --dport 995 -j ACCEPT
iptables -A FORWARD -s $external_mail -d $workstation_net -p tcp -m state
    --state ESTABLISHED --sport 1024: -dport 995 -j ACCEPT

## 1.2.4 SSH/SCP
iptables -A FORWARD -s $workstation_net -d $external_cluster -p tcp -m state \
    --state NEW,ESTABLISHED --sport 1024: --dport 22 -j ACCEPT
iptables -A FORWARD -s $external_cluster -d $workstation_net -p tcp -m state \
    --state ESTABLISHED --sport 22 --dport 1024: -j ACCEPT

## 1.2.5 FTP Only passive is allowed
iptables -A FORWARD -s $workstation_net -d $internal_ftp -p tcp -m state \
    --state NEW,ESTABLISHED --sport 1024: --dport 20,21 -j ACCEPT
iptables -A FORWARD -s $internal_ftp -d $workstation_net -p tcp -m state \
    --state ESTABLISHED --sport 20,21 --dport 1024: -j ACCEPT

## 1.2.6 
### SSH to firewall from admin server
iptables -A INPUT -s $internal_admin -d $fw_eth0 --dport 22 --sport 1024: -j ACCEPT
iptables -A OUTPUT -s $fw_eth0 -d $internal_admin --dport 1024: --sport 22 -j ACCEPT
### ICMP ping from admin to workstations
iptables -A FORWARD -s $internal_admin -d $workstation_net -p icmp \
    --icmp-type 8 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s $workstation_net -d $internal_admin -p icmp \
    --icmp-type 0 -m state --state ESTABLISHED -j ACCEPT

# Endings - YOU SHALL NOT PASS!
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
