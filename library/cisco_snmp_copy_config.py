#!/usr/bin/python

# Copyright 2015 Patrick Ogenstad <patrick@ogenstad.com>
# Copyright 2015 Jim Nagy <jnagy@corp.nac.net>
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

module: cisco_snmp_copy_config
author: Patrick Ogenstad (@networklore)
author: Jim Nagy (@jimnagy)
short_description: Copies the configuration.
description:
    - Copies running or startup config to/from tftp.
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
    source:
        description:
            - Source for the device config
        choices: [ 'tftp', 'startup-config', 'running-config' ]
        required: true
    destination:
        description:
            - Destination for the device config
        choices: [ 'tftp', 'startup-config', 'running-config' ]
        required: true
    tftp_ip:
        description:
            - IP address of the tftp server
        required: false 
    filename:
        description:
            - Filename for the config file
        required: false
'''

EXAMPLES = '''
# Copy running config to a tftp server with SNMPv2
- cisco_snmp_copy_config: host={{ inventory_hostname }} version=2c community=private source=running-config destination=tftp tftp_ip=192.168.1.100 filename=backup.cfg

# Copy backup config from tftp server to startup config with SNMPv3
- cisco_snmp_copy_config:
    host={{ inventory_hostname }}
    version=3
    level=authPriv
    integrity=sha
    privacy=aes
    username=snmp-user
    authkey=abc12345
    privkey=def6789
    source=tftp
    destination=startup-config
    tftp_ip=192.168.1.100
    filename=backup.cfg
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

def copy_config(dev,module,source,destination,tftp_ip,filename):

    filetype = {
        'tftp': 1,
        'startup-config': 3,
        'running-config': 4,
    }
    try:
        # Set source file type
        dev.set(o.ccCopySourceFileType + ".1", filetype[source])

        # Set destination file type
        dev.set(o.ccCopyDestFileType + ".1", filetype[destination])

        if tftp_ip and filename and (source == 'tftp' or destination =='tftp'):
            #  Protocol = tftp
            dev.set(o.ccCopyProtocol + ".1", 1)

            #  Filename
            dev.set(o.ccCopyFileName + ".1", filename, "OctetString")

            #  Server Address
            dev.set(o.ccCopyServerAddress + ".1", tftp_ip, "IpAddress")

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
                    # destroy the object if we failed
                    dev.set(o.ccCopyEntryRowStatus + ".1", 6)
                    module.fail_json(msg="Config copy failed")
        # Destroy the object
        dev.set(o.ccCopyEntryRowStatus + ".1", 6)
    except Exception, err:
        # destroy the object if we failed
        dev.set(o.ccCopyEntryRowStatus + ".1", 6)
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
            source=dict(required=True, choices=['startup-config', 'running-config', 'tftp']),
            destination=dict(required=True, choices=['startup-config', 'running-config', 'tftp']),
            tftp_ip=dict(required=False, default=False),
            filename=dict(required=False, default=False),
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

    if m_args['source'] == "tftp" or m_args['destination'] == "tftp":
        if not m_args['tftp_ip'] or not m_args['filename']:
            module.fail_json(msg='tftp_ip and filename are required when source or destination is tftp')

    nelsnmp_args = {}
    for key in m_args:
        if key in NELSNMP_PARAMETERS and m_args[key] != None:
            nelsnmp_args[key] = m_args[key]

    try:
        dev = SnmpHandler(**nelsnmp_args)
    except Exception, err:
        module.fail_json(msg=str(err))

    return_status = copy_config(dev,module,m_args['source'],m_args['destination'],m_args['tftp_ip'],m_args['filename'])
 
    module.exit_json(**return_status)
    

main()

