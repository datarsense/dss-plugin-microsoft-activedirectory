# import the base class for the custom dataset
import binascii
import json
import ldap3
from impacket_ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from impacket_uuid import bin_to_string
from six.moves import xrange
from dataiku.connector import Connector
from wconv.uac import UserAccountControl


class GetADUserAccounts(Connector):
    def __init__(self, config, plugin_config):
        Connector.__init__(self, config, plugin_config)
        self.ldap_server_fqdn = self.plugin_config.get("ldap_server_fqdn")
        self.ldap_server_port = self.plugin_config.get("ldap_server_port")
        self.use_tls = self.plugin_config.get("use_tls")
        self.anonymous_bind = self.plugin_config.get("anonymous_bind")
        self.bind_dn = self.plugin_config.get("bind_dn")
        self.bind_password = self.plugin_config.get("bind_password")
        self.base_dn = config.get("base_dn")

        # LDAP_SERVER_SD_FLAGS_OID - 0x07 flag value, queries for all values in nTSecurityDescriptor apart from SACL
        self.controls = [('1.2.840.113556.1.4.801', True, "\x30\x03\x02\x01\x07")]  # SACL is 0x8, owner 0x1, group 0x2, DACL 0x4

        self.ace_flags = self.get_ace_flag_constants()
        self.access_masks = self.get_access_mask_constants()
        self.ace_data_flags = self.get_ace_data_flag_constants()

        # impacket LDAP access mask structures have values for set (not read) operations for these masks, so we override
        # https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
        self.am_overrides = {
            'GENERIC_READ' : 0x00020094,
            'GENERIC_WRITE': 0x00020028,
            'GENERIC_EXECUTE':0x00020004,
            'GENERIC_ALL': 0x000F01FF
        }
        
        # start with well known SIDS https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
        self.sidLT = {
            'S-1-0': ['Null Authority', 'User'],
            'S-1-0-0': ['Nobody', 'User'],
            'S-1-1': ['World Authority', 'User'],
            'S-1-1-0': ['Everyone', 'Group'],
            'S-1-2': ['Local Authority', 'User'],
            'S-1-2-0': ['Local', 'Group'],
            'S-1-2-1': ['Console Logon', 'Group'],
            'S-1-3': ['Creator Authority', 'User'],
            'S-1-3-0': ['Creator Owner', 'User'],
            'S-1-3-1': ['Creator Group', 'Group'],
            'S-1-3-2': ['Creator Owner Server', 'Computer'],
            'S-1-3-3': ['Creator Group Server', 'Computer'],
            'S-1-3-4': ['Owner Rights', 'Group'],
            'S-1-4': ['Non-unique Authority', 'User'],
            'S-1-5': ['NT Authority', 'User'],
            'S-1-5-1': ['Dialup', 'Group'],
            'S-1-5-2': ['Network', 'Group'],
            'S-1-5-3': ['Batch', 'Group'],
            'S-1-5-4': ['Interactive', 'Group'],
            'S-1-5-6': ['Service', 'Group'],
            'S-1-5-7': ['Anonymous', 'Group'],
            'S-1-5-8': ['Proxy', 'Group'],
            'S-1-5-9': ['Enterprise Domain Controllers', 'Group'],
            'S-1-5-10': ['Principal Self', 'User'],
            'S-1-5-11': ['Authenticated Users', 'Group'],
            'S-1-5-12': ['Restricted Code', 'Group'],
            'S-1-5-13': ['Terminal Server Users', 'Group'],
            'S-1-5-14': ['Remote Interactive Logon', 'Group'],
            'S-1-5-15': ['This Organization', 'Group'],
            'S-1-5-17': ['IUSR', 'User'],
            'S-1-5-18': ['Local System', 'User'],
            'S-1-5-19': ['NT Authority', 'User'],
            'S-1-5-20': ['Network Service', 'User'],
            'S-1-5-80-0': ['All Services ', 'Group'],
            'S-1-5-32-544': ['Administrators', 'Group'],
            'S-1-5-32-545': ['Users', 'Group'],
            'S-1-5-32-546': ['Guests', 'Group'],
            'S-1-5-32-547': ['Power Users', 'Group'],
            'S-1-5-32-548': ['Account Operators', 'Group'],
            'S-1-5-32-549': ['Server Operators', 'Group'],
            'S-1-5-32-550': ['Print Operators', 'Group'],
            'S-1-5-32-551': ['Backup Operators', 'Group'],
            'S-1-5-32-552': ['Replicators', 'Group'],
            'S-1-5-32-554': ['Pre-Windows 2000 Compatible Access', 'Group'],
            'S-1-5-32-555': ['Remote Desktop Users', 'Group'],
            'S-1-5-32-556': ['Network ConfiguratiManagedServiceAccountn Operators', 'Group'],
            'S-1-5-32-557': ['Incoming Forest Trust Builders', 'Group'],
            'S-1-5-32-558': ['Performance Monitor Users', 'Group'],
            'S-1-5-32-559': ['Performance Log Users', 'Group'],
            'S-1-5-32-560': ['Windows Authorization Access Group', 'Group'],
            'S-1-5-32-561': ['Terminal Server License Servers', 'Group'],
            'S-1-5-32-562': ['Distributed COM Users', 'Group'],
            'S-1-5-32-568': ['IIS_IUSRS', 'Group'],
            'S-1-5-32-569': ['Cryptographic Operators', 'Group'],
            'S-1-5-32-573': ['Event Log Readers', 'Group'],
            'S-1-5-32-574': ['Certificate Service DCOM Access', 'Group'],
            'S-1-5-32-575': ['RDS Remote Access Servers', 'Group'],
            'S-1-5-32-576': ['RDS Endpoint Servers', 'Group'],
            'S-1-5-32-577': ['RDS Management Servers', 'Group'],
            'S-1-5-32-578': ['Hyper-V Administrators', 'Group'],
            'S-1-5-32-579': ['Access Control Assistance Operators', 'Group'],
            'S-1-5-32-580': ['Remote Management Users', 'Group'],
            'S-1-5-32-581': ['Default Account', 'Group'],
            'S-1-5-32-582': ['Storage Replica Administrators', 'Group'],
            'S-1-5-32-583': ['Device Owners', 'Group']
        }


    def get_read_schema(self):
        return None

    def generate_rows(self, dataset_schema=None, dataset_partitioning=None,
                      partition_id=None, records_limit=-1):
        server = ldap3.Server(self.ldap_server_fqdn, get_info=ldap3.ALL, port=self.ldap_server_port, use_ssl=self.use_tls)

        if self.anonymous_bind:
            connection = ldap3.Connection(server)
            connection.bind()
        else:
            connection = ldap3.Connection(server, user=self.bind_dn, password=self.bind_password)

        # perform the Bind operation
        if not connection.bind():
            raise Exception('Error during LDAP bind' + connection.result)

        entries = connection.extend.standard.paged_search(self.base_dn, '(&(objectClass=user)(!(objectClass=computer)))', attributes='*', paged_size=500, controls=self.controls, generator=True)

        for entry in entries:
            if 'attributes' in entry:
                entry_dict = dict(entry['attributes'])

                # Convert userAccountControl integer to himan readable flags using https://github.com/qtc-de/wconv
                if 'userAccountControl' in entry_dict:
                    entry_dict['userAccountControl'] = UserAccountControl.parse_flags(entry_dict['userAccountControl'])

                # Parse ntSecurityDescriptor
                try:
                    nTSecurityDescriptor = entry_dict['nTSecurityDescriptor']
                    entry_dict['nTSecurityDescriptor'] = self.parseSecurityDescriptor(nTSecurityDescriptor)
                except Exception as e:
                    print('Error in parsing security descriptor data in field {}: {}'.format(entry_dict['nTSecurityDescriptor'], str(e)))

                # Stream entry
                # Convert entry to dict and use default=str to convert datetime objects to string
                yield json.loads(json.dumps(entry_dict, default=str))

    def get_writer(self, dataset_schema=None, dataset_partitioning=None, partition_id=None):
        raise NotImplementedError

    def get_partitioning(self):
        raise NotImplementedError

    def list_partitions(self, partitioning):
        return []

    def partition_exists(self, partitioning, partition_id):
        raise NotImplementedError

    def get_records_count(self, partitioning=None, partition_id=None):
        raise NotImplementedError

    def parseSecurityDescriptor(self, nTSecurityDescriptor):
        out = {}
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(nTSecurityDescriptor)
        out['IsACLProtected'] = int(bin(sd['Control'])[2:][3]) == 1 # 3 PD DACL Protected from inherit operations
        # Get-ADUser -Filter * -Properties nTSecurityDescriptor | ?{ $_.nTSecurityDescriptor.AreAccessRulesProtected -eq "True" }
        # sd['Sacl'] is masked in the LDAP query because of permissions, so wont be available here
        if sd['Control']:
            out['Control'] = sd['Control']
        if sd['OwnerSid']:
            out['OwnerSid'] = sd['OwnerSid'].formatCanonical()
            if out['OwnerSid'] in self.sidLT:
                out['OwnerName'] = self.sidLT[out['OwnerSid']][0]
        if sd['GroupSid']:
            out['GroupSid'] = sd['GroupSid'].formatCanonical()
            if out['GroupSid'] in self.sidLT:
                out['GroupName'] = self.sidLT[out['GroupSid']][0]
        if sd['Dacl']:
            out['Dacls'] = []
            for ace in sd['Dacl']['Data']:
                dacl = {'Type' : ace['TypeName']}
                dacl['Sid'] = ace['Ace']['Sid'].formatCanonical()
                if dacl['Sid'] in self.sidLT:
                    d = [self.sidLT[dacl['Sid']][0]]
                    domainsid = self.get_domain_sid(dacl['Sid'])
                    #if domainsid in self.domainLTNB:
                    #    d.append(self.domainLTNB[domainsid])
                    #elif dacl['Sid'].startswith('S-1-5-32-'):
                    if dacl['Sid'].startswith('S-1-5-32-'):
                        d.append('Builtin')
                    dacl['ResolvedSidName'] = '\\'.join(d[::-1])
                    dacl['Foreign'] = False
                #elif dacl['Sid'].count('-') > 6: # this is wrong...
                #    dacl['Foreign'] = True

                dacl['Flags'] = []
                for flag in self.ace_flags:
                    if ace.hasFlag(self.ace_flags[flag]):
                        dacl['Flags'].append(flag)
                if dacl['Type'] == 'ACCESS_ALLOWED_OBJECT_ACE':
                    dacl['Ace_Data_Flags'] = []
                    for dataflag in self.ace_data_flags:
                        if ace['Ace'].hasFlag(self.ace_data_flags[dataflag]):
                            dacl['Ace_Data_Flags'].append(dataflag)

                dacl['Mask'] = ace['Ace']['Mask']['Mask']

                dacl['Privs'] = []
                for priv in self.access_masks:
                    if ace['Ace']['Mask'].hasPriv(self.access_masks[priv]):
                        dacl['Privs'].append(priv)
                #if 'ObjectType' in ace['Ace'].fields and len(ace['Ace']['ObjectType']) > 0:
                    #type_guid = bin_to_string(ace['Ace']['ObjectType']).lower()
                    #if type_guid in self.object_types:
                    #    dacl['ControlObjectType'] = self.object_types[type_guid]
                    #else:
                    #    dacl['ControlObjectType'] = type_guid
                #if 'InheritedObjectType' in ace['Ace'].fields and len(ace['Ace']['InheritedObjectType']) > 0:
                    #type_guid = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    #if type_guid in self.object_types:
                    #    dacl['InheritableObjectType'] = self.object_types[type_guid]
                    #else:
                    #    dacl['InheritableObjectType'] = type_guid
                out['Dacls'].append(dacl)

        return out
    
    def get_domain_sid(self, sid):
        return '-'.join(sid.split('-')[:-1])
    
    def get_ace_flag_constants(self):
        return {a:ACE.__dict__[a] for a in ACE.__dict__ if a == a.upper()} 

    def get_access_mask_constants(self):
        access_mask = {a:ACCESS_MASK.__dict__[a] for a in ACCESS_MASK.__dict__ if a == a.upper() }
        access_mask.update({a:ACCESS_ALLOWED_OBJECT_ACE.__dict__[a] for a in ACCESS_ALLOWED_OBJECT_ACE.__dict__ if a.startswith('ADS_')})   
        #access_mask.update(self.am_overrides)
        return access_mask


    def get_ace_data_flag_constants(self):
        return {a:ACCESS_ALLOWED_OBJECT_ACE.__dict__[a] for a in ACCESS_ALLOWED_OBJECT_ACE.__dict__ if 'PRESENT' in a}
    
    
    
    
