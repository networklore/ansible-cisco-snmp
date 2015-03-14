#!/usr/bin/python

# Copyright 2015 Patrick Ogenstad <patrick@ogenstad.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
            - Typically set to {{ inventory_hostname }}
        required: true
    version:
        description:
            - SNMP Version to use, 2c or 3
        choices: [ '2c', '3' ]
        required: true
    community:
        description:
            - The SNMP community string, required if version is 2c
        required: false
    level:
        description:
            - Authentication level, required if version is 3
        choices: [ 'authPriv', 'authNoPriv' ]
        required: false
    username:
        description:
            - Username for SNMPv3, required if version is 3
        required: false
    integrity:
        description:
            - Hashing algoritm, required if version is 3
        choices: [ 'md5', 'sha' ]
        required: false
    authkey:
        description:
            - Authentication key, required if version is 3
        required: false
    privacy:
        description:
            - Encryption algoritm, required if level is authPriv
        choices: [ 'des', '3des', 'aes', 'aes192', 'aes256' ]
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
    version=3
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
    from nelsnmp.snmp import SnmpHandler
    import nelsnmp.cisco_oids
    o = nelsnmp.cisco_oids.CiscoOids()  
    has_nelsnmp = True
except:
    has_nelsnmp = False

NELSNMP_PARAMETERS = (
    'host',
    'community',
    'version',
    'level',
    'integrity',
    'privacy',
    'username',
    'authkey',
    'privkey'
)

def create_vlan(dev,vlan_id,vlan_name,module):
    vlan_id = str(vlan_id)
 
    try:
   
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

        vartable = dev.getnext(o.vtpVlanName)
    except Exception, err:
        module.fail_json(msg='Unable to write to device')    

    vlan_created = False
    for varbinds in vartable:
        for oid, val in varbinds:
            current_vlan_id = oid.rsplit('.', 1)[-1]
            current_vlan_name = val
            if vlan_name != False:
                if current_vlan_id == vlan_id:
                    vlan_created = True
            else:    
                if current_vlan_id == vlan_id and current_vlan_name == vlan_name:
                    vlan_created = True
    if not vlan_created:
        module.fail_json(msg="Unable to create VLAN, check SNMP write access")

def delete_vlan(dev,vlan_id,module):
    vlan_id = str(vlan_id)

    try:
        dev.set(o.vtpVlanEditOperation + ".1", 2)
        dev.set(o.vtpVlanEditRowStatus + ".1." + vlan_id, 6)
        dev.set(o.vtpVlanEditOperation + ".1", 3)
        dev.set(o.vtpVlanEditOperation + ".1", 4)
        vartable = dev.getnext(o.vtpVlanState)
    except Exception, err:
        module.fail_json(msg='Unable to write to device')    

    for varbinds in vartable:
        for oid, val in varbinds:
            current_vlan_id = oid.rsplit('.', 1)[-1]
            if current_vlan_id == vlan_id:
                module.fail_json(msg="Unable to delete VLAN from device, check SNMP write access")


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            version=dict(required=True, choices=['2c', '3']),
            community=dict(required=False, default=False),
            username=dict(required=False),
            level=dict(required=False, choices=['authNoPriv', 'authPriv']),
            integrity=dict(required=False, choices=['md5', 'sha']),
            privacy=dict(required=False, choices=['des', '3des', 'aes', 'aes192', 'aes256']),
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
    if m_args['version'] == "2c":
        if m_args['community'] == False:
            module.fail_json(msg='Community not set when using snmp version 2')
            
    if m_args['version'] == "3":
        if m_args['username'] == None:
            module.fail_json(msg='Username not set when using snmp version 3')

        if m_args['level'] == "authPriv" and m_args['privacy'] == None:
            module.fail_json(msg='Privacy algorithm not set when using authPriv')

    nelsnmp_args = {}
    for key in m_args:
        if key in NELSNMP_PARAMETERS and m_args[key] != None:
            nelsnmp_args[key] = m_args[key]

    try:
        dev = SnmpHandler(**nelsnmp_args)
    except Exception, err:
        module.fail_json(msg=str(err))

    changed_false = { 'changed': False }                           
    changed_true = { 'changed': True }                           

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
            create_vlan(dev,m_args['vlan_id'],vlan_defined_name, module)
        else:
            # Remove vlan
            delete_vlan(dev, m_args['vlan_id'],module)


 
    module.exit_json(**return_status)
    

main()

