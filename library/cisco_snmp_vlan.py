#!/usr/bin/python

DOCUMENTATION = '''
---

module: cisco_snmp_vlan
author: Patrick Ogenstad (@networklore)
short_description: Create or delete vlans.
description:
    - Creates, deletes or renames VLANs on a Cisco switch using SNMP.
requirements:
    - nelsnmp
options:
    host:
        description:
            - Typically set to {{ inventory_hostname }}}
        required: true
    version:
        description:
            - SNMP Version to use, v2/v2c or v3
        choices: [ 'v2', 'v2c', 'v3' ]
        required: true
    community:
        description:
            - The SNMP community string, required if version is v2/v2c
        required: false
    level:
        description:
            - Authentication level, required if version is v3
        choices: [ 'authPriv', 'authNoPriv' ]
        required: false
    username:
        description:
            - Username for SNMPv3, required if version is v3
        required: false
    integrity:
        description:
            - Hashing algoritm, required if version is v3
        choices: [ 'md5', 'sha' ]
        required: false
    authkey:
        description:
            - Authentication key, required if version is v3
        required: false
    privacy:
        description:
            - Encryption algoritm, required if level is authPriv
        choices: [ 'des', 'aes' ]
        required: false
    privkey:
        description:
            - Encryption key, required if version is authPriv
        required: false
'''

EXAMPLES = '''
# Create or rename vlan 12, give it the name GUESTS
- cisco_snmp_vlan: host={{ inventory_hostname }} version=2c community=private vlan_id=12 state=present vlan_name="GUESTS"

# Delete vlan 40 if present
- cisco_snmp_vlan:
    host={{ inventory_hostname }}
    version=v3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    vlan_id=40
    state=absent
'''

from ansible.module_utils.basic import *
from collections import defaultdict

try:
    import nelsnmp.snmp
    import nelsnmp.cisco_oids
    o = nelsnmp.cisco_oids.CiscoOids()
   
    has_nelsnmp = True
except:
    has_nelsnmp = False

def create_vlan(dev,vlan_id,vlan_name):
    vlan_id = str(vlan_id)
    
    dev.set(o.vtpVlanEditOperation + ".1", 2)
    dev.set(o.vtpVlanEditBufferOwner + ".1", "Ansible")

    dev.set(o.vtpVlanEditRowStatus + ".1." + vlan_id, 4)

    dev.set(o.vtpVlanEditType + ".1." + vlan_id, 1)

    if vlan_name != False:
        dev.set(o.vtpVlanEditName + ".1." + vlan_id, vlan_name)

    # Is this really needed?
    #snmp_set = (tuple(s.vtpVlanEditDot10Said + [1] + [vlan_id]), rfc1902.OctetString('0x000186ab'))
    #dev.set(snmp_set)

    dev.set(o.vtpVlanEditOperation + ".1", 3)
    # Verify that the work is done
    dev.set(o.vtpVlanEditOperation + ".1", 4)


def delete_vlan(dev,vlan_id):
    vlan_id = str(vlan_id)

    dev.set(o.vtpVlanEditOperation + ".1", 2)
    dev.set(o.vtpVlanEditRowStatus + ".1." + vlan_id, 6)
    dev.set(o.vtpVlanEditOperation + ".1", 3)
    dev.set(o.vtpVlanEditOperation + ".1", 4)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            version=dict(required=True, choices=['v2', 'v2c', 'v3']),
            community=dict(required=False, default=False),
            username=dict(required=False),
            level=dict(required=False, choices=['authNoPriv', 'authPriv']),
            integrity=dict(required=False, choices=['md5', 'sha']),
            privacy=dict(required=False, choices=['des', 'aes']),
            authkey=dict(required=False),
            privkey=dict(required=False),
            state=dict(required=True, choices=['absent', 'present']),
            vlan_id=dict(required=True),
            vlan_name=dict(required=False),
            removeplaceholder=dict(required=False)),
            required_together = ( ['username','level','integrity','authkey'],['privacy','privkey'],),
        supports_check_mode=False)

    m_args = module.params

    if not has_nelsnmp:
        module.fail_json(msg='Missing required nelsnmp module (check docs)')

    # Verify that we receive a community when using snmp v2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        if m_args['community'] == False:
            module.fail_json(msg='Community not set when using snmp version 2')
            
    if m_args['version'] == "v3":
        if m_args['username'] == None:
            module.fail_json(msg='Username not set when using snmp version 3')

        if m_args['level'] == "authPriv" and m_args['privacy'] == None:
            module.fail_json(msg='Privacy algorithm not set when using authPriv')

            
        if m_args['integrity'] == "sha":
            integrity_proto = cmdgen.usmHMACSHAAuthProtocol
        elif m_args['integrity'] == "md5":
            integrity_proto = cmdgen.usmHMACMD5AuthProtocol

        if m_args['privacy'] == "aes":
            privacy_proto = cmdgen.usmAesCfb128Protocol
        elif m_args['privacy'] == "des":
            privacy_proto = cmdgen.usmDESPrivProtocol
    
    # Use SNMP Version 2
    if m_args['version'] == "v2" or m_args['version'] == "v2c":
        dev = nelsnmp.snmp.SnmpHandler(version='2c', host=m_args['host'],
                               community=m_args['community'])

    # Use SNMP Version 3 with authNoPriv
    elif m_args['level'] == "authNoPriv":
        snmp_auth = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], authProtocol=integrity_proto)

    # Use SNMP Version 3 with authPriv
    else:
        snmp_auth = cmdgen.UsmUserData(m_args['username'], authKey=m_args['authkey'], privKey=m_args['privkey'], authProtocol=integrity_proto, privProtocol=privacy_proto)

    #Tree = lambda: defaultdict(Tree)
    changed_false = { 'changed': False }                           
    changed_true = { 'changed': True }                           
    #results = Tree()
    vlan_defined_name = False

    oids = []
    oids.append(o.vtpVlanState)
    if m_args['vlan_name']:
        oids.append(o.vtpVlanName)
        vlan_defined_name = m_args['vlan_name']
    exists_vlan_id = False
    exists_vlan_name = False
    try:
        vartable = dev.getnext(*oids)
    except Exception, err:
        module.fail_json(msg=str(err))

    for varbinds in vartable:
        for oid, val in varbinds:

            if o.vtpVlanState in oid:
                vlan_id = oid.rsplit('.', 1)[-1]
                if vlan_id == m_args['vlan_id']:
                    exists_vlan_id = True
            if o.vtpVlanName in oid:
                vlan_id = oid.rsplit('.', 1)[-1]
                if vlan_id == m_args['vlan_id']:
                    if m_args['vlan_name'] == val:
                        exists_vlan_name = True

    return_status = changed_true


    if m_args['state'] == "present":
        if m_args['vlan_name'] and exists_vlan_name:
            return_status = changed_false
            desired_state = True
        elif m_args['vlan_name'] and not exists_vlan_name:
            desired_state = False
        elif exists_vlan_id:
            return_status = changed_false
            desired_state = True
        else:
            desired_state = False




    if m_args['state'] == "absent":
        if exists_vlan_id:
            desired_state = False
        else:
            desired_state = True
            return_status = changed_false

    if not desired_state:
        vartable = dev.getnext(o.vtpVlanEditTable)
        if len(vartable) > 0:
            module.fail_json(msg='Other changes are being made to the vlan database')

        if m_args['state'] == "present":
            # Create vlan
            create_vlan(dev,m_args['vlan_id'],vlan_defined_name)
        else:
            # Remove vlan
            delete_vlan(dev, m_args['vlan_id'])


 
    module.exit_json(**return_status)
    

main()

