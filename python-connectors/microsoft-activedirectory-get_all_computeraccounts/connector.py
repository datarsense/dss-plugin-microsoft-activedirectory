# import the base class for the custom dataset
import json
import ldap3
from six.moves import xrange
from dataiku.connector import Connector
from wconv.uac import UserAccountControl


class GetADComputerAccounts(Connector):
    def __init__(self, config, plugin_config):
        Connector.__init__(self, config, plugin_config)
        self.ldap_server_fqdn = self.plugin_config.get("ldap_server_fqdn")
        self.ldap_server_port = self.plugin_config.get("ldap_server_port")
        self.use_tls = self.plugin_config.get("use_tls")
        self.anonymous_bind = self.plugin_config.get("anonymous_bind")
        self.bind_dn = self.plugin_config.get("bind_dn")
        self.bind_password = self.plugin_config.get("bind_password")
        self.base_dn = config.get("base_dn")

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

        entries = connection.extend.standard.paged_search(self.base_dn, '(objectClass=computer)', attributes='*', paged_size=500, generator=True)

        for entry in entries:
            if 'attributes' in entry:
                # Convert entry to dict and use default)str to convert datetime objects to string
                entry_dict = json.loads(json.dumps(dict(entry['attributes']), default=str))

                # Convert userAccountControl integer to himan readable flags using https://github.com/qtc-de/wconv
                entry_dict['userAccountControl'] = UserAccountControl.parse_flags(entry_dict['userAccountControl'])

                #Stream entry
                yield entry_dict

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
