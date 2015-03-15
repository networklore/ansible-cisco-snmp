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

module: cisco_snmp_portsecurity
author: Patrick Ogenstad (@networklore)
short_description: Configures interface settings
description:
    - Configured interface settings
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
    interface_id:
        description:
            - The SNMP interface id (ifIndex)
        required: false
    interface_name:
        description:
            - The name of the interface
        required: false
    portsecurity:
        description:
            - Mode of the interface
        choices: [ 'enabled', 'disabled']
        required: False        
    max:
        description:
            - The maximum number of mac addresses
        required: false
    sticky:
        description:
            - Enable or disable sticky mac addresses
        choices: [ 'enabled', 'disabled']
        required: False        
    violation:
        description:
            - Enable or disable sticky mac addresses
        choices: [ 'shutdown', 'restrict', 'protect']
        required: False        
    aging_type:
        description:
            - Set aging type
        choices: [ 'absolute', 'inactivity']
        required: False        
    aging_time:
        description:
            - Mac address aging time in minutes
        required: false
    aging_static:
        description:
            - Indicates whether the secure MAC address aging mechanism is enabled on static MAC address entries
        choices: [ 'enabled', 'disabled']
        required: False        
'''

EXAMPLES = '''
# Enable Portsecurity on FastEthernet0/2 allow 5 hosts
- cisco_snmp_portsecurity: host={{ inventory_hostname }} version=2c community=private interface_name=FastEthernet0/2 portsecurity=enabled max=5

# Disable Portsecurity on interface 10001
- cisco_snmp_portsecurity:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    interface_id=10001
    portsecurity=disabled
    max=1
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

TRUTHVALUE = {
    'enabled': 1,
    'disabled': 2
}

VIOLATION = {
    'shutdown': 1,
    'restrict': 2,
    'protect': 3
}

AGING_TYPE = {
    'absolute': 1,
    'inactivity': 2
}

def changed_status(changed, has_changed):
    if changed == True:
        has_changed = True
    return has_changed

def set_state(dev, oid, desired_state, module):
    try:
        current_state = dev.get_value(oid)
    except Exception, err:
        module.fail_json(msg=str(err))

    if current_state == desired_state:
        return False
    else:
        try:
            dev.set(oid, desired_state)
        except:
            module.fail_json(msg='Unable to write to device')
        return True

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
            interface_id=dict(required=False),
            interface_name=dict(required=False),
            portsecurity=dict(required=False, choices=['enabled', 'disabled']),
            max=dict(required=False),
            sticky=dict(required=False, choices=['enabled', 'disabled']),
            violation=dict(required=False, choices=['shutdown', 'restrict', 'protect']),
            aging_type=dict(required=False, choices=['absolute', 'inactivity']),
            aging_time=dict(required=False),
            aging_static=dict(required=False, choices=['enabled', 'disabled']),
            removeplaceholder=dict(required=False),
        ),
        mutually_exclusive=(['interface_id', 'interface_name'],),
        required_one_of=(
            ['interface_id', 'interface_name'],
            ['portsecurity', 'max', 'sticky', 'violation', 'aging_type','aging_time'],
        ),
        required_together=(
            ['username','level','integrity','authkey'],['privacy','privkey'],
        ),
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

    has_changed = False

    if m_args['interface_name']:
        # Do this through cache in the future
        try:
            interface = False
            vartable = dev.getnext(o.ifDescr)

            for varbinds in vartable:
                for oid, val in varbinds:
                    if m_args['interface_name'] == val:
                        interface = oid.rsplit('.', 1)[-1]

            if interface == False:
                module.fail_json(msg='Unable to find interface')
        except Exception, err:
            module.fail_json(msg=str(err))

    # Check how to get the interface value
    if m_args['interface_id']:
        interface = m_args['interface_id']

    if m_args['portsecurity']:
        oid = o.cpsIfPortSecurityEnable + "." + str(interface)
        desired_state = TRUTHVALUE[m_args['portsecurity']]
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['max']:
        oid = o.cpsIfMaxSecureMacAddr + "." + str(interface)
        desired_state = int(m_args['max'])
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['sticky']:
        oid = o.cpsIfStickyEnable + "." + str(interface)
        desired_state = TRUTHVALUE[m_args['sticky']]
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['violation']:
        oid = o.cpsIfViolationAction + "." + str(interface)
        desired_state = VIOLATION[m_args['violation']]
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['aging_type']:
        oid = o.cpsIfSecureMacAddrAgingType + "." + str(interface)
        desired_state = AGING_TYPE[m_args['aging_type']]
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['aging_time']:
        oid = o.cpsIfSecureMacAddrAgingTime + "." + str(interface)
        desired_state = int(m_args['aging_time'])
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    if m_args['aging_static']:
        oid = o.cpsIfStaticMacAddrAgingEnable + "." + str(interface)
        desired_state = TRUTHVALUE[m_args['aging_static']]
        changed = set_state(dev, oid, desired_state, module)
        has_changed = changed_status(changed, has_changed)

    return_status = { 'changed': has_changed }

    module.exit_json(**return_status)

    

main()

