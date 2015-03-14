#!/usr/bin/python

DOCUMENTATION = '''
---

module: cisco_snmp_cdp
author: Patrick Ogenstad (@networklore)
short_description: Changes CDP state globally or on an interface
description:
    - Changes CDP globally, i.e. "cdp run" or "no cdp run". On a single interface the module controlls the "cdp enable" or "no cdp enable" setting.
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
    cdp_global:
        description:
            - Global CDP mode
        choices: [ 'enabled', 'disabled']
        required: False
    interface_id:
        description:
            - The SNMP interface id (ifIndex)
        required: false
    interface_name:
        description:
            - The name of the interface
        required: false
    cdp_interface:
        description:
            - The mode of CDP on an individual interface
        choices: [ 'enabled', 'disabled']
        required: False
'''

EXAMPLES = '''
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

CDP_STATE = {
    'enabled': 1,
    'disabled': 2
}

def changed_status(changed, has_changed):
    if changed == True:
        has_changed = True
    return has_changed

def set_cdp_global(dev, cdp_mode, module):
    oid = o.cdpGlobalRun + ".0"
    try:
        
        current_cdp_state = dev.get_value(oid)
    except Exception, err:
        module.fail_json(msg=str(err))

    if current_cdp_state == CDP_STATE[cdp_mode]:
        return False
    else:
        try:
            dev.set(oid,CDP_STATE[cdp_mode])
        except:
            module.fail_json(msg='Unable to write to device')
        return True

def set_cdp_interface(dev, interface, cdp_mode, module):
    oid = o.cdpInterfaceEnable + "." + str(interface)
    try:
        
        current_cdp_state  = dev.get_value(oid)
    except Exception, err:
        module.fail_json(msg=str(err))

    if current_cdp_state  == CDP_STATE[cdp_mode]:
        return False
    else:
        try:
            dev.set(oid,CDP_STATE[cdp_mode])
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
            cdp_global=dict(required=False, choices=['enabled', 'disabled']),
            cdp_interface=dict(required=False, choices=['enabled', 'disabled']),
            interface_id=dict(required=False),
            interface_name=dict(required=False),
            removeplaceholder=dict(required=False),
        ),
        mutually_exclusive=(['interface_id', 'interface_name', 'cdp_global'],['cdp_interface', 'cdp_global']),
        required_one_of=(['interface_id', 'interface_name', 'cdp_global'],['cdp_interface', 'cdp_global']),
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

    if m_args['cdp_global']:
        changed = set_cdp_global(dev, m_args['cdp_global'], module)
        has_changed = changed_status(changed, has_changed)
  
    if m_args['cdp_interface']:
        changed = set_cdp_interface(dev, interface, m_args['cdp_interface'], module)
        has_changed = changed_status(changed, has_changed)
  


    return_status = { 'changed': has_changed }

    module.exit_json(**return_status)

    

main()

