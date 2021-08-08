#!/bin/sh
# A plugin to check SSHD compliance with checkmk
# Digital Governance Agency - DGA 2021
# by Nika Chkhkvishvili
# License: GPL 2
# version 1.0

###zzz

# locate self & dir
_self="${0##%/*}"
dir=${_self%/*}
config="/usr/lib/check_mk_agent/local/global.conf"
# get OS Major version to downlod template accordingly
releasever=$(rpm -E %{rhel})

uniqid=$(uuidgen | cut -d\- -f1)


# get global variables &  auth credentials:
. $config



# configs:
sshd_config_template="/tmp/sshd_config.$uniqid"
sshd_runtime_config="/tmp/sshd_runtime.$uniqid"
sshd_err_file="/tmp/sshd_err.$uniqid"


# fetch config template from repository
if !  curl --fail --silent $curl_opts -X GET  --header 'PRIVATE-TOKEN: '"$token"''\
        "$git_url/api/v4/projects/$project_id/repository/files/ssh%2Fconfig%2Fsshd_config.el$releasever/raw?ref=$ref"\
        --output $sshd_config_template;
then 
    status=2
    statustxt=CRITICAL
    perf_state=1
    message="ID: $uniqid unable to fetch SSH config: sshd_config.el$releasever  templates from git."
    printf "%s"  "$status SSHD-Compliance - $statustxt - $message" | tr -d '\n'
    echo ""
    exit
    fi

  

#transform templplate file, remove comments, blank lines, whitespaces and convert to lowercase
  sed -i 's/#.*$//;/^$/d;s/\(.*\)/\L\1/' $sshd_config_template

# dump SSH runtime config, transoft and save  to file:
sshd -T | sed -e 's/\(.*\)/\L\1/' > $sshd_runtime_config

# read line by line and compare
while IFS= read -r line
do
     if ! grep -q -- "$line" $sshd_runtime_config 
     then
                printf "%s"  "$line\\n" >>$sshd_err_file
                vs_err=1
fi
done < "$sshd_config_template"

# check errors and concatenate if many:
if [[ $vs_err -eq 1 ]];then 
       #chekmk stuff
       status=2
       statustxt=CRITICAL
       perf_state=1
       message="ID: $uniqid Following SSH parametrer[s] in: sshd_config.el$releasever aren't compliant: $(cat $sshd_err_file)"
else
       status=0
       statustxt=OK
       perf_state=0
       message="ID: $uniqid SSH config: sshd_config.el$releasever is compliant."

fi


printf "%s"  "$status SSHD-Compliance - $statustxt - $message" | tr -d '\n'
echo ""


# clean up:
unlink $sshd_err_file
unlink $sshd_config_template
unlink $sshd_runtime_config
unlink $sshd_err_file

