# Linux service config templates for compliance checkup
### services like: SSH, HTTPD, Postfix, etc..

# High Level Architecture:

![Alt text](images/service_configs.png?raw=true "HLA")



<img src="https://docs.checkmk.com/latest/images/CEE.svg"  width="64" height="64">

## Distribution via the Agent Bakery
If you want to distribute a local check to multiple hosts, and you already use the Agent Bakery, the bakery can also be used
```bash
[root@check ~]# su - sitever1
OMD[sitever1]:~$ cd ~/local/share/check_mk/agents
OMD[sitever1]:~/local/share/check_mk/agents$ mkdir -p custom/DGA-custom-checks/lib/local/
```
The lib-directory flags the script as a plug-in or as a local check. The following directory then allocates the file explicitly. You can then also save the local check in this.

Thereafter ***DGA-custom-checks*** will be shown as an option in WATO. Using the *Host & Service Parameters > Monitoring Agents > Generic Options > Deploy custom files with agent* in WATO create a new rule and select the newly-created group:
<img src="https://docs.checkmk.com/latest/images/localchecks_custom.png" width="100%" >

Checkmk will then autonomously integrate the local check correctly into the installation packet for the appropriate operating system. After the changes have been activated and the agent baked, the configuration will be complete. Now the agents only need to be distributed.



### Selinux Issue on EL6:
on el6 systems automatic agent update blocked by selinux: "SELinux is preventing /bin/rpm from using the transition access on a process."
this can be allowed by writing custom Selinux Module:
creatie **T**ype **E**nforement policy file:  **checkmk-agent-bakery-module_v1.te** and add following configuraion:

```python
module checkmk-agent-bakery-module 1.0;
require {
        type rpm_script_t;
        type inetd_child_t;
        class process transition;
}
#============= inetd_child_t ==============
allow inetd_child_t rpm_script_t:process transition;
```

1. create Selinux module .mod file from policy *.te
```bash
[root@system ~]# checkmodule -M -m -o checkmk-agent-bakery-module_v1.mod checkmk-agent-bakery-module_v1.te
```
2. create a SELinux policy module package from a binary policy module:
```bash
[root@system ~]# semodule_package -o checkmk-agent-bakery-module_v1.pp -m checkmk-agent-bakery-module_v1.mod
```
3. install created SELinux policy module checkmk-agent-bakery-module_v1.pp:
```bash
[root@system ~]# semodule -i  checkmk-agent-bakery-module_v1.pp
```

add following line in **/etc/crontab** to pull changes from git autoomatically to bake agenets.

```bash
*/1 * * * * sitever1  cd ~/local/share/check_mk/agents/custom/DGA-custom-checks/lib/local && /usr/bin/git pull -q origin master

```


# individual checks:
## check_iptables.sh
- [x] check if iptables service is running
  - [x] compare CHAIN policies
  - [x] Compare MGMT  ACCESS policies
  - [x] Compare OTHER ACCESS policies
- [x] check if iptables service is enabled
#### HOW IPTABLES rule comparison works (logic):
#### part1 (management access)
  0. **22 is The King**
  1. get IP who has (22 OR ALL OR TCP) ACCESS from RUNTIME
  2. get IP whos has 22 access from TRANS 
  3. if 22 IP[s] from trans dosnt matches with rule 1, throw error
#### part2 (other destination port access)
  1. get ports from template config except port 22.
  2. grep this ports against runtime config and extract coresponding ips from runtime config.
  3. compare extracetd ip to template ip[s].
  4. is mismatch trow error.

# Examples in checkmk:
### iptables is  compliant
![Alt text](images/iptables-ok.png?raw=true "iptables OK")
### iptables is not compliant
![Alt text](images/iptables-error.png?raw=true "iptables OK")
### iptables & sshd is compliant
![Alt text](images/services-ok.png?raw=true "iptables & sshd  OK")
### sshd is not compliant
![Alt text](images/sshd-err.png?raw=true "sshd ERR")



