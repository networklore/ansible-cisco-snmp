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

module: cisco_snmp_save_config
author: Patrick Ogenstad (@networklore)
short_description: Saves the configuration.
description:
    - Saves running configuration to startup configuration.
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
'''

from ansible.module_utils.basic import *
from collections import defaultdict

try:
    from nelsnmp.snmp import SnmpHandler
    from nelsnmp.vendors.cisco.oids import CiscoOids
    o = CiscoOids()
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

def save_config(dev,module):

    try:
        # Source = running config
        dev.set(o.ccCopySourceFileType + ".1", 4)

        # Destination = startup config
        dev.set(o.ccCopyDestFileType + ".1", 3)

        # Run job
        dev.set(o.ccCopyEntryRowStatus + ".1", 1)

        done = False
        while done != True:
            varbinds = dev.get(o.ccCopyState + ".1")

            for oid, value in varbinds:
                if value == 3:
                    # Success
                    done = True
                if value == 4:
                    module.fail_json(msg="Unable to save config")
        # Destroy the object
        dev.set(o.ccCopyEntryRowStatus + ".1", 6)
    except Exception, err:
        module.fail_json(msg='Unable to write to device')


    return { 'changed': True }

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

    return_status = save_config(dev,module)

    module.exit_json(**return_status)


main()
