#!/bin/sh
# A plugin to check IPTABLES compliance with checkmk
# Digital Governance Agency - DGA 2021
# by Nika Chkhkvishvili
# License: GPL 2
# version 1.0

# locate self & dir
_self="${0##%/*}"
dir=${_self%/*}
def_IFS=$IFS
config="/usr/lib/check_mk_agent/local/global.conf"
# get OS Major version to downlod template accordingly
releasever=$(rpm -E %{rhel})
uniqid=$(uuidgen | cut -d\- -f1)

# get global variables &  auth credentials:
. $config


iptables_raw_config_template="/tmp/iptables_raw_config_template.$uniqid"
iptables_config_template="/tmp/iptables_config_template.$uniqid"
iptables_trans_config="/tmp/iptables_trans.$uniqid"
iptables_runtime_config="/tmp/iptables_runtime.$uniqid"
iptables_error_msg="/tmp/iptables_err.$uniqid"
vs_err=0

# error reporting function:
function print_state(){

if [[ $1 -eq 1 ]];then     
       #chekmk stuff
       status=2
       statustxt=CRITICAL
       perf_state=1
       message=$(cat $iptables_error_msg)
else
       status=0
       statustxt=OK
       perf_state=0
       message="IPTABLES config: iptables_config is compliant."

fi
       printf "%s"  "$status IPTABLES-Compliance - $statustxt - $message" | tr -d '\n'
       echo ""

# clean up:
unlink $iptables_raw_config_template >/dev/null 2>&1
unlink $iptables_config_template >/dev/null 2>&1
unlink $iptables_trans_config >/dev/null 2>&1
unlink $iptables_runtime_config >/dev/null 2>&1
unlink $iptables_error_msg >/dev/null 2>&1
exit 0
}


function get_service_running_state(){

if [[ $releasever -eq 6 ]];
  then
    if ! /sbin/lsmod | grep -qc iptable_filter
       then
            echo "IPTABLES is NOT RUNING on this system" >>$iptables_error_msg
            vs_err=1
            print_state $vs_err
    fi
elif [[ $releasever -eq 7 ]];
 then
    if ! grep -qw active <<< $(/usr/bin/systemctl status iptables.service | grep -Po "Active:.*" | awk '{print $2}')
      then
            echo "IPTABLES is NOT RUNING on this system" >>$iptables_error_msg
            vs_err=1
            print_state $vs_err
    fi        
fi

}

#555

function get_service_state(){

if [[ $releasever -eq 6 ]]; 
  then
    if !  /sbin/chkconfig --list iptables  | grep -qwc 3:on
       then 
            echo "IPTABLES is NOT enabled on this system" >>$iptables_error_msg
            vs_err=1
            print_state $vs_err
    fi
fi

}


get_service_running_state

# fetch config template from repository
if ! curl --fail --silent $curl_opts -X GET  --header 'PRIVATE-TOKEN: '"$token"''\
        "$git_url/api/v4/projects/$project_id/repository/files/iptables%2Fconfig%2Fiptables_config/raw?ref=$ref"\
        --output $iptables_raw_config_template;
then 
    echo "unable to fetch IPTABLES config: iptables_config templates from git." >>$iptables_error_msg
    vs_err=1   
    print_state $vs_err
    fi

# dump iptables runtime config, transform and save to file:
# format runtime CHAIN rules:
IFS=$'\n'; 
 for rule in $(/sbin/iptables -L -n -v  | grep  "Chain ");
    do 
             echo "$rule" | awk '{print $2 " " $4}' 
 done > $iptables_runtime_config

# format runtime ACCEPT rules:
# excludes STATE: ESTABLISHD RELATED, loopback, VRRP
IFS=$'\n'
 for rule in $(/sbin/iptables -L -n -v | grep -Po "ACCEPT     .*" ); 
    do
              echo "$rule"\
              | sed -n '/.*/s/ \+/ /gp'\
              | sed '/\s\s*lo*/d;/\s\s*RELATED,ESTABLISHED*/d;/\s\s*224.0.0.0\/8/d'\
              | sed 's/state\s*[0-9a-zA-Z]*//'\
              |  awk '{print $6 " " $2  " " $8 " " $9 " " $10}'\
              | sed 's/tcp\|udp\|icmp//2g'\
              | sed -n '/.*/s/ \+/ /gp'; 
 done >> $iptables_runtime_config
# remove whitespaces at the end of line
sed -i 's/[[:blank:]]*$//' $iptables_runtime_config

###### TRANSFORMATION:

#transform templplate file, remove comments, blank lines, whitespaces and convert to lowercase
sed -i 's/#.*$//;/^$/d;s/\(.*\)/\L\1/' $iptables_raw_config_template

# get & format default CHAIN rules
sed -nr "/^\[chain-rules\]/ { :l /^\s*[^#].*/ p; n; /^\[/ q; b l; };/\[/d"\
        $iptables_raw_config_template > $iptables_config_template

# get & format general INPUT rules
sed -nr "/^\[general-input-rules\]/ { :l /^\s*[^#].*/ p; n; /^\[/ q; b l; };/\[/d"\
         $iptables_raw_config_template >> $iptables_config_template

# get config for this specific host if exist. get IP Address fro this host and find if exra config exists
sed -nr "/^\[$(ip route get 8.8.8.8 | grep -Po 'src \K\S+')\]/ { :l /^\s*[^#].*/ p; n; /^\[/ q; b l; };/\[/d"\
         $iptables_raw_config_template >> $iptables_config_template

# remove config stanza 
sed -i '/\[/d' $iptables_config_template

# clear file:
truncate -s 0 $iptables_trans_config


# read line by line and compare
while IFS= read -r line
do
# clear  all positional parameters:

# get CHAINs config:
if  grep -qi -- "^input\|forward\|output" <<< "$line";
then
    chain_conf=$(echo $line | sed -e 's/policy//g;s/_=/ /g;s/\(.*\)/\U\1/')
    declare -a "chain_conf_arr=($chain_conf)"
    echo "${chain_conf_arr[0]} ${chain_conf_arr[1]}" >>$iptables_trans_config
    
fi   

# match allowed rule
if  grep -q -- "allowed" <<< "$line";
then
   # breake allow INPUT rules into statements and values:
   rule=$(echo "$line" | grep -Po "(?<=allowed_input_).*" |cut -d\= -f1 | sed -e 's/_/ /g;s/ips//g')
   value=$(echo "$line" | grep -Po "(?<=allowed_input_).*" |cut -d\= -f2)
   # declare array from string
   declare -a "rule_arr=($rule)"
   #echo "ARG1: ${rule_arr[0]}" 
   #echo "ARG2: ${rule_arr[1]}"
   #echo "ARG3: ${rule_arr[2]}"
 # check if protocol is set to ANY
 if echo ${rule_arr[0]} | grep -q "any";
   then 
    proto="all"
 else
    proto="${rule_arr[0]}"
 fi
 # check if port is set to ANY
 if echo ${rule_arr[1]} | grep -q "any"; 
   then
    port=''
 else
    port="dpt:${rule_arr[1]}"
 fi  
   # if value contains more then 1 IP:
   if echo "$value" | grep -q "," ;
     then 
       # duplicate this rule with different ip:
       IFS=' '
       for ip in $(echo $value | sed -e 's/\,/ /g')
        do
     echo  "$ip $proto $port"  >>$iptables_trans_config
       done
    else
        # if value is single IP:
           echo  "$value $proto $port" >>$iptables_trans_config
   fi    
fi
done < "$iptables_config_template"
# remove whitespaces at the end of line
sed -i 's/[[:blank:]]*$//' $iptables_trans_config


#### COMPARISON
declare -a chain_mismatch
IFS=$'\n'
for chain in $( grep -P '\b[A-Z]+\b' $iptables_runtime_config );
 do
    if ! grep -qw $chain <<< $(grep -P '\b[A-Z]+\b'  $iptables_trans_config )
     then
             vs_err=1
             chain_mismatch+=($chain)
       fi
done
#call print_state function
if [[ $vs_err -eq 1 ]];then
       echo "CHAIN MISMATCH DETECTED: ${chain_mismatch[@]} chans not matches with template.">> $iptables_error_msg
       vs_err=1
       print_state $vs_err

fi


# Compare ACCESS RULES:
# LOGIC:
# 0. **22 is The King**
# 1. get IP who has (22 OR ALL OR TCP) ACCESS from RUNTIME
# 2. get IP whos has 22 access from TRANS 
# 3. if 22 IP[s] from trans dosnt matches with rule 1, throw error

# create array for err reporting:
declare -a secure_ip
IFS=$'\n'
for ip in $( grep "dpt\:22\|tcp$\|all$" $iptables_runtime_config | awk '{print $1}');
 do  
    if ! grep -qw $ip <<< $(grep "dpt\:22"  $iptables_trans_config | awk '{print $1}')
     then
             vs_err=1
             secure_ip+=($ip)
    fi

done

if [[ $vs_err -eq 1 ]];then
       echo "FOUND EXTRA IP ACCESS: ${secure_ip[@]} which was not declared in iptables template.">> $iptables_error_msg
       vs_err=1
       print_state $vs_err
       
fi        

# check access ports except port 22
#  1. get ports from template config except port 22.
#  2. grep this ports against runtime config and extract coresponding ips from runtime config.
#  3. compare extracetd ip to template ip[s].
#  4. is mismatch trow error.
# create array for err reporting:
declare -a dport_ip
for dport in $(grep -Po "dpt\:.*" $iptables_trans_config | grep -v dpt:22 )
 do 
    for ip in $(grep $dport $iptables_runtime_config | awk '{print $1}')
     do
        if !  grep -q $ip $iptables_trans_config; 
         then
             vs_err=1
             dport_ip+=($ip)
             err_port=$dport
        fi
    
    done
done

if [[ $vs_err -eq 1 ]];then
       echo "FOUND EXTRA DPORT ACCESS on PORT: $(echo $err_port| cut -d\: -f2) with IP: ${dport_ip[@]} which was not declared in iptables template.">> $iptables_error_msg
       vs_err=1
       print_state $vs_err

fi




# check iptables enabled or not on system
get_service_state
print_state $vs_err
