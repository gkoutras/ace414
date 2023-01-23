#!/bin/bash

domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function adBlock() {

    if [ "$EUID" -ne 0 ]; then
        printf "Please run as root.\n"
        exit 1
    fi

    # finding different and same domains in 'domainNames.txt' and 'domainsNames2.txt' files and
	# writing them in 'IPAddressesDifferent.txt' and 'IPAddressesSame.txt' respectively
    if [ "$1" = "-domains" ]; then
        if [ -s $domainNames ] && [ -s $domainNames2 ]; then

            # for the same domains in 'domainNames.txt' and 'domainsNames2.txt'
            readarray arrSame < <(grep -Fxf $domainNames $domainNames2)
            for domain in "${arrSame[@]}"; do
                dig +short $domain | grep '^[.0-9]*$' >> $IPAddressesSame
            done

            # for the different domains in 'domainNames.txt' and 'domainsNames2.txt'
            readarray arrDiff < <(grep -Fxvf $domainNames $domainNames2 && grep -Fxvf $domainNames2 $domainNames)
            for domain in "${arrDiff[@]}"; do
                dig +short $domain | grep '^[.0-9]*$' >> $IPAddressesDifferent
            done

        else
            printf "Files 'domainNames.txt' and 'domainNames2.txt' missing or empty. Exiting...\n"
            exit 1
        fi
        true
    
    # configuring the DROP adblock rule based on the IP addresses of 'IPAddressesSame.txt' file
    elif [ "$1" = "-ipssame" ]; then
        if [ -s $IPAddressesSame ]; then
            while IFS= read -r ip; do
                iptables -A INPUT -s $ip -j DROP
            done < $IPAddressesSame
        else
            printf "File 'IPAddressesSame.txt' missing or empty. Exiting...\n"
            exit 1
        fi
        true

    # configuring the REJECTED adblock rule based on the IP addresses of 'IPAddressesDifferent.txt' file
    elif [ "$1" = "-ipsdiff" ]; then
        if [ -s $IPAddressesDifferent ]; then
            while IFS= read -r ip; do
                iptables -A INPUT -s $ip -j REJECT
            done < $IPAddressesDifferent
        else
            printf "File 'IPAddressesDifferent.txt' missing or empty. Exiting...\n"
            exit 1
        fi
        true
    
    # saving rules to 'adblockRules' file
    elif [ "$1" = "-save" ]; then
        if [ -s $IPAddressesSame ] && [ -s $IPAddressesDifferent ]; then
            iptables-save > $adblockRules
        else
            printf "Files 'IPAddressesSame.txt' and 'IPAddressesDifferent.txt' missing or empty. Exiting...\n"
            exit 1
        fi
        true

    # loading rules to 'adblockRules' file  
    elif [ "$1" = "-load" ]; then
        if [ -s $adblockRules ]; then
            iptables-restore < $adblockRules
        else
            printf "File 'adblockRules' missing or empty. Exiting...\n"
            exit 1
        fi
        true
    
    # listing current rules
    elif [ "$1" = "-list" ]; then
        if [ -s $adblockRules ]; then
            iptables -L
        else
            printf "File 'adblockRules' missing or empty. Exiting...\n"
            exit 1
        fi
        true
    
    # reseting rules to default settings
    elif [ "$1" = "-reset" ]; then
        if [ -s $IPAddressesSame ] && [ -s $IPAddressesDifferent ]; then

            # for IP addresses in 'IPAddressesSame.txt'
            while IFS= read -r ip; do
                iptables -D INPUT -s $ip -j DROP
            done < $IPAddressesSame

            # for IP addresses in 'IPAddressesDifferent.txt'
            while IFS= read -r ip; do
                iptables -D INPUT -s $ip -j REJECT
            done < $IPAddressesDifferent

        else
            printf "Files 'IPAddressesSame.txt' and 'IPAddressesDifferent.txt' missing or empty. Exiting...\n"
            exit 1
        fi
        true

    # printing options
    elif [ "$1" = "-help" ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	    printf "  -ipsdiff\t  Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
