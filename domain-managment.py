#!/usr/bin/env python3

URL = 'https://rpc.gandi.net/xmlrpc/'

import xmlrpc.client, argparse, signal, sys, pprint
from time import sleep
from datetime import datetime

class Domain:
    def __init__(self, api, api_key, handle, name):
        '''
        http://doc.rpc.gandi.net/domain/faq.html#how-to-manage-your-zones
        '''
        self.api               = api
        self.api_key           = api_key
        self.handle            = handle
        self.name              = name
        self.registered        = False
        self.available         = self.check_availability()
        self.infos             = {}
        self.hosts             = [] # Useless ?
        self.zone              = {}
        self.records           = {}
        self.next_zone_version = 0

        #self.get_infos()
        #self.get_current_zone()
        #self.get_zone_records()

    def __repr__(self):
        return """
            name: {}
            api_key: {}
            handle: {}
            registered: {}
            available: {}
            infos: {}
            hosts: {}
            zone: {}
            records: {}
        """.format(
            self.name,
            self.api_key,
            self.handle,
            self.registered,
            self.available,
            self.infos,
            self.hosts,
            self.zone,
            self.records,
            )

    def check_availability(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.available
        '''
        result = self.api.domain.available(self.api_key, [self.name])
        while result[self.name] == 'pending':
            sleep(1)
            result = self.api.domain.available(self.api_key, [self.name])
        if result[self.name] == 'available':
            return True
        return False
    
    def register(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.create
        http://doc.rpc.gandi.net/operation/reference.html#operation.info
        http://doc.rpc.gandi.net/hosting/reference_iface.html#OperationReturn
        '''
        domain_spec = {
            'owner': self.handle,
            'admin': self.handle,
            'bill':  self.handle,
            'tech':  self.handle,
            'duration': 1
        }
        op = self.api.domain.create(
            self.api_key,
            self.name,
            domain_spec
        )
        result = self.api.operation.info(self.api_key, op['id'])
        while result['step'] in ['BILL', 'WAIT', 'RUN']:
            print("Waiting for registration to process. Curent status:", result['step'])
            sleep(1)
            result = self.api.operation.info(self.api_key, op['id'])

        if result['step'] == 'DONE':
            print("Domain", self.name, "is registered")
            self.registered = True
            return True

        print("Domain is not registered. Status:", result['step'])
        self.registered = False
        return False

    def get_infos(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.info
        '''
        self.infos = self.api.domain.info(self.api_key, self.name)

    def get_hosts(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.host.list
        '''
        self.hosts = self.api.domain.host.list(self.api_key, self.name)

    def get_current_zone(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.zone.info
        '''
        self.zone = self.api.domain.zone.info(self.api_key, self.infos['zone_id'])

    def get_zone_records(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.zone.record.list
        '''
        self.records = self.api.domain.zone.record.list(
            self.api_key,
            self.zone['id'],
            self.zone['version']
        )

    def clone_zone(self):
        '''
        http://doc.rpc.gandi.net/domain/faq.html#how-to-manage-your-zones
        '''
        self.zone = self.api.domain.zone.clone(self.api_key, self.infos['zone_id'])

    def create_new_zone_version(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.zone.clone
        '''
        self.next_zone_version = self.api.domain.zone.version.new(
            self.api_key, self.zone['id']
        )

    def update_zone(self, record, rtype, rtarget):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.zone.version.new
        '''
        new_record = {
            'type':  rtype,
            'name':  record,
            'value': rtarget+'.',
            'ttl':   600
        }
        pprint.pprint(new_record)
        self.api.domain.zone.record.add(
            self.api_key, self.zone['id'],
            self.next_zone_version,
            new_record
        )

    def set_zone(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.zone.version.set
        '''
        self.api.domain.zone.version.set(self.api_key, self.zone['id'], self.next_zone_version)
        if self.infos['zone_id'] != self.zone['id']:
            self.api.domain.zone.set(self.api_key, self.name, self.zone['id'])

    def renew(self):
        '''
        http://doc.rpc.gandi.net/domain/reference.html#domain.renew
        '''
        op = self.api.domain.renew(
            self.api_key,
            self.name,
            {
                'duration': 1,
                'current_year': self.infos['date_registry_end'].year
            }
        )
        result = self.api.operation.info(self.api_key, op['id'])
        while result['step'] in ['BILL', 'WAIT', 'RUN']:
            print("Waiting for renewal to process. Curent status:", result['step'])
            sleep(1)
            result = self.api.operation.info(self.api_key, op['id'])

        if result['step'] == 'DONE':
            print("Domain", self.name, "is renewed")
            return True

        print("Error while registering domain. Operation status is", result['step'])
        return False



def main(api_key, handle, domain, action, record=None, rtype=None, rtarget=None):
    api = xmlrpc.client.ServerProxy(URL, use_builtin_types=True)
    my_domain = Domain(api, api_key, handle, domain)

    if action == 'register':
        if not my_domain.available:
            print("Error: domain", domain, "is not available")
            sys.exit(1)
        my_domain.register()
        sys.exit(0)

    my_domain.get_infos()
    my_domain.get_current_zone()
    my_domain.get_zone_records()

    if action == 'renew':
        my_domain.renew()
        sys.exit(0)

    if action == 'add_record':
        if None in [record, rtype, rtarget]:
            print("Error: One or more arguments are missing. Please read help")
            sys.exit(1)

        for cur_record in my_domain.records:
            if cur_record['name'] == record:
                print("Record already exists in zone")
                sys.exit(1)

        if my_domain.zone['owner'] == None:
            my_domain.clone_zone()
        my_domain.create_new_zone_version()
        my_domain.update_zone(record, rtype, rtarget)
        my_domain.set_zone()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api_key", help="api key used to connect to Gandi's API",
                                                                    required=True)
    parser.add_argument("--handle",  help="handle used to associate domain with",
                                                                    required=True)
    parser.add_argument("--domain",  help="domain on which action has to be performed",
                                                                    required=True)
    parser.add_argument("--action",  help="action to perform", choices=["register", "renew", "add_record"],
                                                                    required=True)
    parser.add_argument("--record",  help="if action is add_record, specifiy wich record to add",
                                                                    required=False,
                                                                    default=None)
    parser.add_argument("--rtype",   help="if action is add_record, specifiy wich type of record to add",
                                                                    choices=["A", "CNAME"],
                                                                    required=False,
                                                                    default=None)
    parser.add_argument("--rtarget", help="if action is add_record, specifiy wich target the record is pointing to",
                                                                    required=False,
                                                                    default=None)

    args = parser.parse_args()

    main(
        args.api_key,
        args.handle,
        args.domain,
        args.action,
        args.record,
        args.rtype,
        args.rtarget
    )
