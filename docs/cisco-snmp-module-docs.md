# Cisco SNMP Ansible Module Docs
### *Manage Cisco IOS devices with Ansible using SNMP*

---
### Requirements
 * Check the [README](../README.md#Dependencies)

---
### Modules

  * [cisco_snmp_cdp - changes cdp state globally or on an interface](#cisco_snmp_cdp)
  * [cisco_snmp_interface - configures interface settings](#cisco_snmp_interface)
  * [cisco_snmp_save_config - saves the configuration.](#cisco_snmp_save_config)
  * [cisco_snmp_switchport - configures switchport settings](#cisco_snmp_switchport)
  * [cisco_snmp_vlan - create or delete vlans.](#cisco_snmp_vlan)

---

## cisco_snmp_cdp
Changes CDP state globally or on an interface

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Changes CDP globally, i.e. "cdp run" or "no cdp run". On a single interface the module controlls the "cdp enable" or "no cdp enable" setting.
 nelsnmp

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  Username for SNMPv3, required if version is 3  |
| level  |   no  |  | <ul> <li>authPriv</li>  <li>authNoPriv</li> </ul> |  Authentication level, required if version is 3  |
| cdp_interface  |   no  |  | <ul> <li>enabled</li>  <li>disabled</li> </ul> |  The mode of CDP on an individual interface  |
| privacy  |   no  |  | <ul> <li>des</li>  <li>3des</li>  <li>aes</li>  <li>aes192</li>  <li>aes256</li> </ul> |  Encryption algoritm, required if level is authPriv  |
| community  |   no  |  | |  The SNMP community string, required if version is 2c  |
| interface_id  |   no  |  | |  The SNMP interface id (ifIndex)  |
| authkey  |   no  |  | |  Authentication key, required if version is 3  |
| host  |   yes  |  | |  Typically set to {# inventory_hostname #}  |
| version  |   yes  |  | <ul> <li>2c</li>  <li>3</li> </ul> |  SNMP Version to use, 2c or 3  |
| cdp_global  |   no  |  | <ul> <li>enabled</li>  <li>disabled</li> </ul> |  Global CDP mode  |
| interface_name  |   no  |  | |  The name of the interface  |
| integrity  |   no  |  | <ul> <li>md5</li>  <li>sha</li> </ul> |  Hashing algoritm, required if version is 3  |
| privkey  |   no  |  | |  Encryption key, required if version is authPriv  |

#### Examples
```
# Disables CDP from running (i.e. 'no cdp run')
- cisco_snmp_cdp: host={{ inventory_hostname }} version=2c community=private cdp_global=disabled

# Enables CDP on GigabitEthernet0/1
- cisco_snmp_cdp:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    interface_name=GigabitEthernet0/1
    cdp_interface=enabled

# Disables CDP on GigabitEthernet0/2
- cisco_snmp_cdp:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    interface_name=GigabitEthernet0/2
    cdp_interface=disabled


```


---


## cisco_snmp_interface
Configures interface settings

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Configured interface settings
 nelsnmp

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  Username for SNMPv3, required if version is 3  |
| description  |   no  |  | |  The description of the interface  |
| level  |   no  |  | <ul> <li>authPriv</li>  <li>authNoPriv</li> </ul> |  Authentication level, required if version is 3  |
| privacy  |   no  |  | <ul> <li>des</li>  <li>3des</li>  <li>aes</li>  <li>aes192</li>  <li>aes256</li> </ul> |  Encryption algoritm, required if level is authPriv  |
| community  |   no  |  | |  The SNMP community string, required if version is 2c  |
| interface_id  |   no  |  | |  The SNMP interface id (ifIndex)  |
| authkey  |   no  |  | |  Authentication key, required if version is 3  |
| host  |   yes  |  | |  Typically set to {# inventory_hostname #}  |
| version  |   yes  |  | <ul> <li>2c</li>  <li>3</li> </ul> |  SNMP Version to use, 2c or 3  |
| admin_state  |   no  |  | <ul> <li>up</li>  <li>down</li> </ul> |  Mode of the interface  |
| interface_name  |   no  |  | |  The name of the interface  |
| integrity  |   no  |  | <ul> <li>md5</li>  <li>sha</li> </ul> |  Hashing algoritm, required if version is 3  |
| privkey  |   no  |  | |  Encryption key, required if version is authPriv  |

#### Examples
```
# Change description and shutdown FastEthernet0/2
- cisco_snmp_interface: host={{ inventory_hostname }} version=2c community=private interface_name=FastEthernet0/2 description="NOT IN USE" admin_state=down

# Change description and enable interface with id 10001
- cisco_snmp_interface:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    interface_id=10001
    description=AP1
    admin_state=up

```


---


## cisco_snmp_save_config
Saves the configuration.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Saves running configuration to startup configuration.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  Username for SNMPv3, required if version is 3  |
| level  |   no  |  | <ul> <li>authPriv</li>  <li>authNoPriv</li> </ul> |  Authentication level, required if version is 3  |
| privacy  |   no  |  | <ul> <li>des</li>  <li>3des</li>  <li>aes</li>  <li>aes192</li>  <li>aes256</li> </ul> |  Encryption algoritm, required if level is authPriv  |
| community  |   no  |  | |  The SNMP community string, required if version is 2c  |
| authkey  |   no  |  | |  Authentication key, required if version is 3  |
| host  |   yes  |  | |  Typically set to {# inventory_hostname #}  |
| version  |   yes  |  | <ul> <li>2c</li>  <li>3</li> </ul> |  SNMP Version to use, 2c or 3  |
| integrity  |   no  |  | <ul> <li>md5</li>  <li>sha</li> </ul> |  Hashing algoritm, required if version is 3  |
| privkey  |   no  |  | |  Encryption key, required if version is authPriv  |

#### Examples
```
# Save configuration with SNMPv2
- cisco_snmp_save_config: host={{ inventory_hostname }} version=2c community=private

# Save configuration with SNMPv3
- cisco_snmp_save_config:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789

```


---


## cisco_snmp_switchport
Configures switchport settings

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Configured switchport setting such as port mode and vlans.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  Username for SNMPv3, required if version is 3  |
| access_vlan  |   no  |  | |  The access vlan id  |
| level  |   no  |  | <ul> <li>authPriv</li>  <li>authNoPriv</li> </ul> |  Authentication level, required if version is 3  |
| native_vlan  |   no  |  | |  The native vlan id on a trunk port  |
| privacy  |   no  |  | <ul> <li>des</li>  <li>3des</li>  <li>aes</li>  <li>aes192</li>  <li>aes256</li> </ul> |  Encryption algoritm, required if level is authPriv  |
| community  |   no  |  | |  The SNMP community string, required if version is 2c  |
| interface_id  |   no  |  | |  The SNMP interface id (ifIndex)  |
| authkey  |   no  |  | |  Authentication key, required if version is 3  |
| host  |   yes  |  | |  Typically set to {# inventory_hostname #}  |
| version  |   yes  |  | <ul> <li>2c</li>  <li>3</li> </ul> |  SNMP Version to use, 2c or 3  |
| mode  |   yes  |  | <ul> <li>access</li>  <li>trunk</li>  <li>desirable</li>  <li>auto</li>  <li>trunk-nonegotiate</li> </ul> |  Mode of the interface  |
| interface_name  |   no  |  | |  The name of the interface  |
| integrity  |   no  |  | <ul> <li>md5</li>  <li>sha</li> </ul> |  Hashing algoritm, required if version is 3  |
| privkey  |   no  |  | |  Encryption key, required if version is authPriv  |

#### Examples
```
# Set interface with id 10001 to access mode in vlan 12
- cisco_snmp_switchport: host={{ inventory_hostname }} version=2c community=private interface_id=10001 mode=access access_vlan=12

# Change FastEthernet0/2 to trunk mode using native vlan 12
- cisco_snmp_switchport:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    mode=trunk
    interface_name="FastEthernet0/2"
    native_vlan=12

```


---


## cisco_snmp_vlan
Create or delete vlans.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Creates, deletes or renames VLANs on a Cisco switch using SNMP.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  Username for SNMPv3, required if version is 3  |
| level  |   no  |  | <ul> <li>authPriv</li>  <li>authNoPriv</li> </ul> |  Authentication level, required if version is 3  |
| privacy  |   no  |  | <ul> <li>des</li>  <li>3des</li>  <li>aes</li>  <li>aes192</li>  <li>aes256</li> </ul> |  Encryption algoritm, required if level is authPriv  |
| community  |   no  |  | |  The SNMP community string, required if version is 2c  |
| authkey  |   no  |  | |  Authentication key, required if version is 3  |
| host  |   yes  |  | |  Typically set to {# inventory_hostname #}  |
| version  |   yes  |  | <ul> <li>2c</li>  <li>3</li> </ul> |  SNMP Version to use, 2c or 3  |
| integrity  |   no  |  | <ul> <li>md5</li>  <li>sha</li> </ul> |  Hashing algoritm, required if version is 3  |
| privkey  |   no  |  | |  Encryption key, required if version is authPriv  |

#### Examples
```
# Create or rename vlan 12, give it the name GUESTS
- cisco_snmp_vlan: host={{ inventory_hostname }} version=2c community=private vlan_id=12 state=present vlan_name="GUESTS"

# Delete vlan 40 if present
- cisco_snmp_vlan:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    vlan_id=40
    state=absent

```


---


---
Documentation generated with [Ansible Webdocs](https://github.com/jedelman8/ansible-webdocs).
