#!/bin/sh
# check SELinux status on host
# by Nika Chkhikvishvili
# 2018

state=$(getenforce)

if [[ "$state" != "Enforcing" ]]; then 
       status=2
       statustxt=CRITICAL
       perf_state=1
else
       status=0
       statustxt=OK
       perf_state=0
fi

 echo "$status SELinux state=$perf_state;1;1 $state"
