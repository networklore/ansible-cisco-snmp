## About

This repo contains [Ansible](https://github.com/ansible/ansible) modules which use SNMP to change configuration on Cisco devices. The repo is currently in a proof of concept stage to see how you can manage older devices (which doesn't have a fancy api) with modern IT automation tools. Over at Networklore there's more information about the [Ansible for Cisco IOS SNMP modules](http://networklore.com/ansible-cisco-snmp/).

## Goal

The goal of this project is to provide idempotent modules for older Cisco devices.

## Alpha code

Currently this is only a test and there's a good chance that a lot of the code will change.

## Dependencies

These modules requires:

* [pysnmp](http://pysnmp.sourceforge.net) 4.2.5 or later
* [nelsnmp](https://github.com/networklore/nelsnmp)
* A good old Cisco switch/router

## Installation of Ansible module
```
pip install nelsnmp
```
As new modules are added you will need to update nelsnmp to support newer MIBs.
```
pip install nelsnmp --upgrade
```
If you are running Ansible through a Python virtualenv you might need to change the ansible_python_interpreter variable. Check the hosts file in this repo for an example. You can clone this repo and copy the modules to your Ansible library path. If you are unsure, check out the [quick start guide](http://networklore.com/ansible-cisco-snmp-install/)

## Configuration of Cisco device

Testing: SNMPv2
```
snmp-server community [write-community-string] rw [acl]
```
Production: SNMPv3
```
ip access-list standard ACL-ANSIBLE-HOST
 permit host 172.29.50.50

snmp-server view V3ISO iso included

snmp-server group ANSIBLEGRP v3 priv write V3ISO

snmp-server user ansible ANSIBLEGRP v3 auth sha AuthPassword123 priv aes 128 PrivPassword123 access ACL-ANSIBLE-HOST
```


## Demo

Running the playbook the first time:

```
$ ansible-playbook -i hosts example-playbooks/how-to/examples-vlan.yml

PLAY [all] ********************************************************************

TASK: [Ensure VLAN 10 is present and has the name INTERNAL] *******************
ok: [172.29.50.5]

TASK: [Ensure VLAN 12 is present and has the name GUESTS] *********************
changed: [172.29.50.5]

TASK: [Ensure that VLAN 40 is created] ****************************************
ok: [172.29.50.5]

TASK: [Remove VLAN 80 if it is present] ***************************************
ok: [172.29.50.5]

TASK: [Create vlan 100 with SNMPv3] *******************************************
ok: [172.29.50.5]

TASK: [Create vlan from variable] *********************************************
changed: [172.29.50.5] => (item={'vlan_id': 30, 'vlan_name': 'red'})
ok: [172.29.50.5] => (item={'vlan_id': 31, 'vlan_name': 'green'})
changed: [172.29.50.5] => (item={'vlan_id': 32, 'vlan_name': 'blue'})

NOTIFIED: [save config] *******************************************************
changed: [172.29.50.5]

PLAY RECAP ********************************************************************
172.29.50.5                : ok=7    changed=3    unreachable=0    failed=0
```

Running the playbook a second time:

```
$ ansible-playbook -i hosts example-playbooks/how-to/examples-vlan.yml

PLAY [all] ********************************************************************

TASK: [Ensure VLAN 10 is present and has the name INTERNAL] *******************
ok: [172.29.50.5]

TASK: [Ensure VLAN 12 is present and has the name GUESTS] *********************
ok: [172.29.50.5]

TASK: [Ensure that VLAN 40 is created] ****************************************
ok: [172.29.50.5]

TASK: [Remove VLAN 80 if it is present] ***************************************
ok: [172.29.50.5]

TASK: [Create vlan 100 with SNMPv3] *******************************************
ok: [172.29.50.5]

TASK: [Create vlan from variable] *********************************************
ok: [172.29.50.5] => (item={'vlan_id': 30, 'vlan_name': 'red'})
ok: [172.29.50.5] => (item={'vlan_id': 31, 'vlan_name': 'green'})
ok: [172.29.50.5] => (item={'vlan_id': 32, 'vlan_name': 'blue'})

PLAY RECAP ********************************************************************
172.29.50.5                : ok=6    changed=0    unreachable=0    failed=0
```

## Todo

* Error handling (the module assumes that the SNMPv3 user/SNMPv2 community has write access to the device)
* Ability to save running configuration to startup configuration
* cisco_snmp_switchport module - Add ability to set allowed VLANs on a trunk

## Known issues

* Naming conflicts: If you try to add a vlan using a name which already exists the module won't pick this up. The vlan will keep it's old name or be created without a name
* No checking if the provided vlan_id is a valid number. I.e. the module won't complain if you try to create a vlan with id 37812942

## Potential roadmap

* Change interfaces i.e. access/trunk port, vlan assignments, description, admin up/down
* Handle configuraion backups
* All other things which might be possible through SNMP

## Feedback

If you have any questions or feedback. Please send me a note over [at my blog](http://networklore.com/contact/) or submit an issue here at Github.
