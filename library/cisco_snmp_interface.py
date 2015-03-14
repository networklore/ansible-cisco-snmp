#!/usr/bin/python

DOCUMENTATION = '''
---

module: cisco_snmp_interface
author: Patrick Ogenstad (@networklore)
short_description: Configures interface settings
description:
    - Configured interface settings
    - nelsnmp
options:
    host:
        description:
            - Typically set to {{ inventory_hostname }}}
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
    admin_state:
        description:
            - Mode of the interface
        choices: [ 'up', 'down']
        required: False
    interface_id:
        description:
            - The SNMP interface id (ifIndex)
        required: false
    interface_name:
        description:
            - The name of the interface
        required: false
    description:
        description:
            - The description of the interface
        required: false
'''

EXAMPLES = '''
# Save configuration with SNMPv2
- cisco_snmp_interface: host={{ inventory_hostname }} version=2c community=private

# Save configuration with SNMPv3
- cisco_snmp_switchport:
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

ADMIN_STATE = {
    'up': 1,
    'down': 2,
    'testing': 3
}



def changed_status(changed, has_changed):
    if changed == True:
        has_changed = True
    return has_changed

def set_interface_admin_status(dev, interface, admin_status, module):
    oid = o.ifAdminStatus + "." + str(interface)
    try:
        # Source = running config
        
        current_admin_status = dev.get_value(oid)
    except Exception, err:
        module.fail_json(msg=str(err))

    if current_admin_status == ADMIN_STATE[admin_status]:
        return False
    else:
        try:
            dev.set(oid,ADMIN_STATE[admin_status])
        except:
            module.fail_json(msg='Unable to write to device')
        return True

def set_interface_description(dev, interface, description, module):
    oid = o.ifAlias + "." + str(interface)
    try:
        # Source = running config
        
        current_description = dev.get_value(oid)
    except Exception, err:
        module.fail_json(msg=str(err))

    if current_description == description:
        return False
    else:
        try:
            dev.set(oid,description)
        except:
            module.fail_json(msg='Unable to write to device')
        return True

    #else:
    #    module.fail_json(msg='Unable to find interface')

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
            admin_state=dict(required=False, choices=['up', 'down']),
            interface_id=dict(required=False),
            interface_name=dict(required=False),
            description=dict(required=False),
            removeplaceholder=dict(required=False),
        ),
        mutually_exclusive=(['interface_id', 'interface_name'],),
        required_one_of=(['interface_id', 'interface_name'],),
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

    #return_status = { 'changed': False }
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

    if m_args['description']:
        changed = set_interface_description(dev, interface, m_args['description'], module)
        has_changed = changed_status(changed, has_changed)
  
    if m_args['admin_state']:
        changed = set_interface_admin_status(dev, interface, m_args['admin_state'], module)
        has_changed = changed_status(changed, has_changed)
  


    return_status = { 'changed': has_changed }

    module.exit_json(**return_status)

    

main()

