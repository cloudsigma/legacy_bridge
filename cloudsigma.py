#! /usr/bin/env python
# coding=utf-8

from __future__ import print_function
from __future__ import unicode_literals
import random
import string

__version__ = "1.0"

import json
import requests
import unittest
import urlparse
from os import environ as os_environ

# You can override these values by running:
# $ export CSAUTH='user@example.com:password'
USERNAME = 'user@example.com'
PASSWORD = 'password'

try:
    DEFAULT_USERNAME, DEFAULT_PASSWORD = os_environ['CSAUTH'].split(':')
except:
    DEFAULT_USERNAME, DEFAULT_PASSWORD = USERNAME, PASSWORD


# You can override this value by running:
# $ export CSURI='https://zrh.cloudsigma.com/api/2.0/'
URL = 'https://zrh.cloudsigma.com/api/2.0/'

try:
    DEFAULT_URL = os_environ['CSURI']
except:
    DEFAULT_URL = URL


def key_in(a_dict, a_keypath):
    """
    Checks whether a_keypath exists in a_dict and it evalutes to True.

    @type a_dict:   dict
    @param a_dict:  Dictionary to check

    @type a_keypath:   list
    @param a_keypath:  List of keys. E.g. ['a', 'b', 'c'] means a_dict['a']['b']['c']

    @rtype:     bool
    @return:    True if key path exist, otherwise False.
    """
    for k in a_keypath:
        if isinstance(a_dict, dict) and k in a_dict:
            a_dict = a_dict[k]
        else:
            return False

    return bool(a_dict)


def set_value_for_keypath(a_dict, a_keypath, a_value):
    """
    Sets a_value for a_keypath in a_dict.

    @type a_dict:   dict
    @param a_dict:  Dictionary to change.

    @type a_keypath:    list
    @param a_keypath:   List of keys. E.g. ['a', 'b', 'c'] means a_dict['a']['b']['c']

    @param a_value:   Value to set for a_keypath
    """
    for k in a_keypath[:-1]:
        a_dict = a_dict.setdefault(k, {})

    a_dict[-1] = a_value


class CloudSigmaLegacy(object):
    """
    Drop-in replacement for legacy cloudsigma bash script to support new API (2.0).
    Parses parameters into new API endpoint and the converts the results into legacy format.

    Usage:
    >>> import cloudsigma
    >>> c = cloudsigma.CloudSigmaLegacy()
    >>> c.drives_list()
    """

    def __init__(self, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD, url=DEFAULT_URL, verbose=False):
        self.username = username
        self.password = password
        self.url = url
        self.verbose = verbose

    def perform(self, a_args, a_payload=""):
        """
        Performs API call using new API.

        @type a_args: list
        @param a_args: List of arguments passed to the legacy cloudsigma.sh as were parsed using ArgParse or OptParse.
                     E.g. ["servers", "a76f0426-0acd-4e3b-94e1-ca64f081bc21", "start"]

        @type a_payload: unicode
        @param a_payload: Optional a_payload as for legacy cloudsigma.sh
                        E.g. "ide:0:0 e135d266-1ba6-4939-8806-d37d63ea974a"

        @rtype: unicode
        @return: String representation of the answer as were returned by cloudsigma.sh

        @raise ValueError: Raises an exception if command is not recognized.
        """
        if a_args[0] == 'drives':
            if len(a_args) == 2:
                if a_args[1] == 'create':
                    return self.drives_create(a_payload)
                elif a_args[1] == 'info':
                    return self.drives_info_all()
                elif a_args[1] == 'list':
                    return self.drives_list()
            elif len(a_args) == 3:
                if a_args[2] == 'clone':
                    return self.drives_clone(a_args[1])
                elif a_args[2] == 'destroy':
                    return self.drives_destroy(a_args[1])
                elif a_args[2] == 'info':
                    return self.drives_info(a_args[1])
        elif a_args[0] == 'servers':
            if len(a_args) == 2:
                if a_args[1] == 'create':
                    return self.servers_create(a_payload)
                elif a_args[1] == 'info':
                    return self.servers_info_all()
                elif a_args[1] == 'list':
                    return self.servers_list()
            elif len(a_args) == 3:
                if a_args[2] == 'destroy':
                    return self.servers_destroy(a_args[1])
                elif a_args[2] == 'info':
                    return self.servers_info(a_args[1])
                elif a_args[2] == 'set':
                    return self.servers_set(a_args[1], a_payload)
                elif a_args[2] == 'start':
                    return self.servers_start(a_args[1])
                elif a_args[2] == 'stop':
                    return self.servers_stop(a_args[1])
        elif a_args[0] == 'resources':
            if len(a_args) == 2 and a_args[1] == 'info':
                return self.resources_vlan_info()
            if len(a_args) == 3 and a_args[1] == 'vlan':
                if a_args[2] == 'info':
                    return self.resources_vlan_info()
                if a_args[2] == 'create':
                    return self.resources_vlan_create(a_payload)

        raise ValueError("Command \"{0}\" is not recognized".format(" ".join(a_args)))

    def make_request(self, a_type, a_endpoint, a_data=None, a_params=None, a_headers=None):
        """
        Makes request by setting appropriate url and auth.

        @type a_type: unicode
        @param a_type: Type of the request (GET, PUT, POST or DELETE)

        @type a_endpoint: unicode
        @param a_endpoint: Endpoint for the request.

        @type a_data: object
        @param a_data: Request's a_data

        @type a_params: dict
        @param a_params: Dict representation of additional parameters.
                         E.g. ['do': start'] will be transformed into "?do=start"

        @type a_headers: dict
        @param a_headers: Headers appended to the request.

        @rtype: requests.models.Response
        """
        a_type = a_type.lower()
        url = urlparse.urljoin(self.url, a_endpoint)

        if self.verbose:
            print(">>> REQUEST")
            print("\tURL:", url)

            if a_headers:
                print("\tHEADERS:", a_headers)

            if a_data:
                print("\tDATA:", str(a_data)[:2048])

        if a_type == 'get':
            response = requests.get(url,
                                    auth=(self.username, self.password),
                                    data=a_data,
                                    headers=a_headers,
                                    params=a_params)
        elif a_type == 'put':
            response = requests.put(url,
                                    auth=(self.username, self.password),
                                    data=a_data,
                                    headers=a_headers,
                                    params=a_params)
        elif a_type == 'post':
            response = requests.post(url,
                                     auth=(self.username, self.password),
                                     data=a_data,
                                     headers=a_headers,
                                     params=a_params)
        elif a_type == 'delete':
            response = requests.delete(url,
                                       auth=(self.username, self.password),
                                       data=a_data,
                                       headers=a_headers,
                                       params=a_data)
        else:
            raise ValueError("{0} is not supported".format(a_type))

        if self.verbose:
            print("<<< RESPONSE")
            print("\tSTATUS CODE:", response.status_code)
            print("\tHEADERS:", response.headers)
            print("\tDATA:", response.content[:2048])
            print("")

        return response

    def drives_clone_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        if not key_in(a_result, ['objects']):
            return ""
        else:
            return self.drives_info_convert_result(a_result['objects'][0])

    def drives_clone(self, a_uuid):
        """
        Clones drive with given a_uuid.

        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('POST', 'drives/{0}/action/'.format(a_uuid), a_params={"do": "clone"})

        if r.status_code == 202:
            return self.drives_clone_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot clone drive: {0}, {1}".format(r.status_code, r.text)

    def drives_create_convert_payload(self, a_payload):
        """
        @type a_payload: unicode

        @rtype: dict
        """
        payload_json = {}

        for line in a_payload.splitlines():
            (key, value) = line.split(" ", 1)

            if key in ['name', 'size', 'tags']:
                payload_json[key] = value
            elif key == 'media':
                payload_json['media'] = value

        payload_json.setdefault('media', 'disk')

        return payload_json

    def drives_create_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        if key_in(a_result, ['objects']):
            return self.drives_info_convert_result(a_result['objects'][0])
        else:
            return ""

    def drives_create(self, a_payload):
        """
        @type a_payload: unicode

        @rtype: unicode
        """
        payload_json = self.drives_create_convert_payload(a_payload)
        r = self.make_request('POST',
                              'drives/',
                              a_data=json.dumps(payload_json),
                              a_headers={'content-type': 'application/json'})
        if r.status_code == 201:
            return self.drives_create_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot create drive: {0}, {1}".format(r.status_code, r.text)

    def drives_destroy_covert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        return ""

    def drives_destroy(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('DELETE', 'drives/{0}/'.format(a_uuid))
        if r.status_code == 204:
            return self.drives_destroy_covert_result(r.json())
        else:
            return "Cannot destroy drive: {0}, {1}".format(r.status_code, r.text)

    def drives_info_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        info = []

        if key_in(a_result, ['status']):
            info.append("status {0}".format(a_result['status']))

        if key_in(a_result, ['name']):
            info.append("name {0}".format(a_result['name']))

        if key_in(a_result, ['owner', 'uuid']):
            info.append("user {0}".format(a_result['owner']['uuid']))

        if key_in(a_result, ['uuid']):
            info.append("drive {0}".format(a_result['uuid']))

        if key_in(a_result, ['media']):
            info.append("type {0}".format(a_result['media']))

        if key_in(a_result, ['size']):
            info.append("size {0}".format(a_result['size']))

        return "\n".join(info)

    def drives_info(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('GET', 'drives/{0}/'.format(a_uuid))

        if r.status_code == 200:
            return self.drives_info_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot return info for drive: {0}, {1}".format(r.status_code, r.text)

    def drives_info_all(self):
        """
        @rtype: unicode
        """
        r = self.make_request('GET', 'drives/')

        if r.status_code == 200:
            result = r.json()

            if not key_in(result, ['objects']):
                return "No drives found."
            else:
                infos = []

                for drive in result['objects']:
                    r = self.make_request('GET', 'drives/{0}/'.format(drive['uuid']))

                    if r.status_code == 200:
                        infos.append(self.drives_info_convert_result(r.json()))
                    else:
                        r.raise_for_status()

                return "\n\n".join(filter(None, infos))
        else:
            r.raise_for_status()
            return "Cannot get drives: {0}, {1}".format(r.status_code, r.text)

    def drives_list_convert_result(self, a_result):
        """
        @type a_result:   dict

        @rtype: unicode
        """
        return "\n".join(filter(None, map(lambda drive: drive['uuid'], a_result['objects'])))

    def drives_list(self):
        """
        @rtype: unicode
        """
        r = self.make_request('GET', 'drives/')

        if r.status_code == 200:
            return self.drives_list_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot list drives: {0}, {1}".format(r.status_code, r.text)

    def servers_create_convert_payload(self, a_payload):
        """
        @type a_payload: unicode

        @rtype: dict
        """
        payload_json = {}

        drives = {}  # "legacy api rep": "new api rep"
        drives_boot_order = ""

        nics = []
        nic0 = {}
        nic1 = {}

        for line in a_payload.splitlines():
            if ' ' in line:
                key, value = line.split(' ', 1)
            else:
                key, value = line, None

            if key in ['name', 'cpu', 'smp']:
                payload_json[key] = value
            elif key == 'mem':
                payload_json[key] = unicode(int(value) * 1024 * 1024)  # in legacy API mem size is specified in MBs
            elif key.startswith('ide') or key.startswith('block') or key.startswith('virtio'):
                # E.g. "ide:1:0" or "virtio:0:0"
                device, dev_channel = key.split(':', 1)

                # New API uses virtio to represent block
                if device == 'block':
                    device = 'virtio'

                # New API requires both channel and controller to be specified (i.e. block:0:0 rather than just block:0)
                if dev_channel.count(':') < 1:
                    dev_channel_int = int(dev_channel[-1])
                    dev_channel_bin = bin(dev_channel_int)[2:].ljust(2, str('0'))
                    dev_channel = ":".join(list(dev_channel_bin))

                drives[key] = {
                    'dev_channel': dev_channel,
                    'device': device,
                    'drive': value
                }
            elif key == 'nic:0:model':
                nic0['model'] = value
            elif key == 'nic:0:dhcp':
                nic0['ip_v4_conf'] = {'conf': 'dhcp'}
            elif key == 'nic:0':
                # TODO: Handle deletion
                pass
            elif key == 'nic:1:model':
                nic1['model'] = value
            elif key == 'nic:1:vlan':
                nic1['vlan'] = value
            elif key == 'nic:1:mac':
                nic1['mac'] = value
            elif key == 'boot':
                # Boot order is specified per drive in new API.
                # Postpone setting boot order unless whole a_payload is parsed
                drives_boot_order = value
            elif key == 'vnc:password':
                payload_json['vnc_password'] = value

        if len(drives_boot_order):
            i = 1  # boot_order value must be positive

            for drive_old_key in drives_boot_order.split():
                drives[drive_old_key]['boot_order'] = i
                i += 1

        if len(drives):
            payload_json['drives'] = drives.values()

        if len(nic0):
            nics.append(nic0)

        if len(nic1):
            nics.append(nic1)

        if len(nics):
            payload_json['nics'] = nics

        return payload_json

    def servers_create_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        objects = [self.servers_info_convert_result(o) for o in a_result['objects']]
        return "\n\n".join(objects)

    def servers_create(self, a_payload):
        """
        @type a_payload:  unicode

        @rtype: unicode
        """
        payload_json = self.servers_create_convert_payload(a_payload)
        payload_json.setdefault('vnc_password', ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(5)))
        r = self.make_request('POST',
                              'servers/',
                              a_data=json.dumps(payload_json),
                              a_headers={'content-type': 'application/json'})

        if r.status_code == 201:
            return self.servers_create_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot create server: {0}, {1}".format(r.status_code, r.text)

    def servers_destroy_covert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        return ""

    def servers_destroy(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('DELETE', 'servers/{0}/'.format(a_uuid))

        if r.status_code == 204:
            return self.servers_destroy_covert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot destroy server: {0}, {1}".format(r.status_code, r.text)

    def servers_info_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        infos = []

        if key_in(a_result, ['status']):
            infos.append("status {0}".format(a_result['status']))

        if key_in(a_result, ['name']):
            infos.append("name {0}".format(a_result['name']))

        if key_in(a_result, ['mem']):
            infos.append("mem {0}".format(int(a_result['mem']) / 1024 / 1024))

        if key_in(a_result, ['vnc_password']):
            infos.append("vnc:password {0}".format(a_result["vnc_password"]))

        if key_in(a_result, ['uuid']):
            infos.append("server {0}".format(a_result["uuid"]))

        if key_in(a_result, ['owner']):
            infos.append("user {0}".format(a_result["owner"]['uuid']))

        if key_in(a_result, ['cpu']):
            infos.append("cpu {0}".format(a_result['cpu']))

        if key_in(a_result, ['drives']):
            drives = []

            for d in a_result['drives']:
                device = d['device']

                # Legacy API uses single number to represent channel and controller of 'block' ('virtio' in new API).
                if d['device'] == 'virtio':
                    device = 'block'
                    dev_channel = d['dev_channel']
                    dev_channel = ''.join(dev_channel.split(':'))
                    dev_channel_int = int(dev_channel)
                    dev_channel = unicode(dev_channel_int)
                else:
                    dev_channel = d['dev_channel']

                drives.append("{0}:{1} {2}".format(device, dev_channel, d['drive']['uuid']))

            if len(drives):
                infos += drives

            boot_drives = filter(lambda drive: 'boot_order' in drive and drive['boot_order'] is not None,
                                 a_result['drives'])
            boot_drives.sort(key=lambda drive: drive['boot_order'])
            boot_drives = map(lambda drive: "{0}:{1}".format(drive['device'], drive['dev_channel']), boot_drives)

            if len(boot_drives):
                infos.append("boot {0}".format(" ".join(boot_drives)))

        if key_in(a_result, ['nics']):
            # nic0 is the first nic without vlan
            for nic in a_result['nics']:
                if not key_in(nic, ['vlan']) and key_in(nic, ['model']):
                    if not key_in(nic, ['ip_v4_conf', 'conf']) and not key_in(nic, ['ip_v4_conf', 'ip']):
                        continue

                    infos.append("nic:0:model {0}".format(nic['model']))

                    if nic['ip_v4_conf']['conf'] == 'dhcp':
                        infos.append("nic:0:dhcp auto")
                    else:
                        infos.append("nic:0:dhcp {0}".format(nic['ip_v4_conf']['ip']))

                    break

            # nic1 is the first nic with vlan
            for nic in a_result['nics']:
                if key_in(nic, ['vlan', 'uuid']) and key_in(nic, ['model']) and key_in(nic, ['mac']):
                    infos.append("nic:1:model {0}".format(nic['model']))
                    infos.append("nic:1:vlan {0}".format(nic['vlan']['uuid']))
                    infos.append("nic:1:mac {0}".format(nic['mac']))

                break

        return "\n".join(infos)

    def servers_info(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('GET', 'servers/{0}/'.format(a_uuid))

        if r.status_code == 200:
            return self.servers_info_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot get server: {0}, {1}".format(r.status_code, r.text)

    def servers_info_all(self):
        """
        @rtype: unicode
        """
        r = self.make_request('GET', 'servers/')

        if r.status_code == 200:
            result = r.json()

            if not key_in(result, ['objects']):
                return "No servers found."
            else:
                infos = []

                for server in result['objects']:
                    r = self.make_request('GET', 'servers/{0}/'.format(server['uuid']))
                    if r.status_code == 200:
                        infos.append(self.servers_info_convert_result(r.json()))
                    else:
                        r.raise_for_status()

                return "\n\n".join(filter(None, infos))
        else:
            r.raise_for_status()
            return "Cannot get servers: {0}, {1}".format(r.status_code, r.text)

    def servers_list_convert_result(self, a_result):
        """
        @type a_result:   dict

        @rtype: unicode
        """
        if key_in(a_result, ['objects']):
            return "\n".join(filter(None, map(lambda s: s['uuid'], a_result['objects'])))
        else:
            return ""

    def servers_list(self):
        r = self.make_request('GET', 'servers/')

        if r.status_code == 200:
            return self.servers_list_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot get servers: {0}, {1}".format(r.status_code, r.text)

    def servers_set_convert_payload(self, a_result):
        """
        @type a_result: unicode

        @rtype: dict
        """
        return self.servers_create_convert_payload(a_result)

    def servers_set_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        return self.servers_info_convert_result(a_result)

    def servers_set(self, a_uuid, a_payload):
        """
        @type a_uuid: unicode

        @type a_payload:  unicode

        @rtype: unicode
        """
        # Partials updates are not supported.
        # We should first get detailed info and then overwrite it.

        r = self.make_request('GET', 'servers/{0}/'.format(a_uuid))

        if r.status_code == 200:
            server_old = r.json()
            server_new = self.servers_set_convert_payload(a_payload)
            # We need to merge nics and drives to preserve them.
            for key, value in server_new.items():
                if key == 'nics':
                    if key_in(server_old, ['nics']):
                        # Only addition is supported for now due to lack of uuids on nics.
                        server_old['nics'] += value
                    else:
                        server_old['nics'] = value
                elif key == 'drives':
                    if key_in(server_old, ['drives']):
                        for drive_new in server_new['drives']:
                            if key_in(drive_new, ['drive']):
                                # uuid is specified, modify some drive that exists.
                                drive_old = None

                                for d in server_old['drives']:
                                    if d['drive']['uuid'] == drive_new['drive']:
                                        drive_old = d
                                        break

                                if drive_old:
                                    drive_old.update(drive_new)
                                else:
                                    server_old['drives'].append(drive_new)
                            else:
                                # uuid is not specified, delete first drive whose device and dev_channel matches.
                                drives_new = []

                                for d in server_old['drives']:
                                    if d['device'] != drive_new['device'] or d['dev_channel'] != drive_new['dev_channel']:
                                        drives_new.append(d)

                                server_old['drives'] = drives_new
                    else:
                        server_old[key] = value
                else:
                    server_old[key] = value

            r = self.make_request('PUT',
                                  'servers/{0}/'.format(a_uuid),
                                  a_data=json.dumps(server_old),
                                  a_headers={'content-type': 'application/json'})

            if r.status_code == 200:
                return self.servers_set_convert_result(r.json())
            else:
                r.raise_for_status()
                return "Cannot set data: {0}, {1}".format(r.status_code, r.text)
        else:
            r.raise_for_status()
            return "Cannot get server: {0}, {1}".format(r.status_code, r.text)

    def servers_start_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        # On success it returns dict:
        # {
        #   "action": "start",
        #   "result": "success",
        #   "uuid": "ef3c7882-1316-4dd9-a5fc-36dd461ddbbb"
        # }
        #
        # On error it returns list:
        # [
        #   {
        #    "error_point": null,
        #    "error_type": "permission",
        #    "error_message": "Cannot start guest in state \"started\". Guest should be in state \"stopped\""
        #   }
        # ]
        return a_result['result']

    def servers_start(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('POST',
                              'servers/{0}/action/'.format(a_uuid),
                              a_params={"do": "start"})

        if r.status_code == 202:
            return self.servers_start_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot start server: {0}, {1}".format(r.status_code, r.text)

    def servers_stop_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        return self.servers_start_convert_result(a_result)

    def servers_stop(self, a_uuid):
        """
        @type a_uuid: unicode

        @rtype: unicode
        """
        r = self.make_request('POST',
                              'servers/{0}/action/'.format(a_uuid),
                              a_params={"do": "stop"})
        if r.status_code == 202:
            return self.servers_stop_convert_result(r.json())
        else:
            r.raise_for_status()
            return "Cannot stop server: {0}, {1}".format(r.status_code, r.text)

    def resources_vlan_create_convert_payload(self, a_payload):
        """
        @type a_payload: unicode

        @rtype: dict
        """
        payload_json = {}

        for line in a_payload.splitlines():
            (key, value) = line.split(" ", 1)

            if key in ['name']:
                payload_json['meta'] = {key: value}

        return payload_json

    def resources_vlan_create_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        return self.resources_vlan_info_convert_result(a_result)

    def resources_vlan_create(self, a_payload):
        """
        @type a_payload: unicode

        @rtype: unicode
        """
        # You cannot actually create vlans via API.
        # You should fist buy them using web UI.
        # Create effectively lists all vlans and just edit one without name.
        r = self.make_request('GET', 'vlans/')

        if r.status_code == 200:
            r_json = r.json()

            if key_in(r_json, ['objects']):
                new_vlan = None

                for v in r_json['objects']:
                    r = self.make_request('GET', 'vlans/{0}/'.format(v['uuid']))
                    r.raise_for_status()

                    if r.status_code == 200:
                        v_detailed = r.json()

                        if not key_in(v_detailed, ['meta', 'name']) or not v_detailed['meta']['name']:
                            new_vlan = v_detailed
                            break

                if new_vlan:
                    r = self.make_request('PUT',
                                          'vlans/{0}/'.format(new_vlan['uuid']),
                                          a_data=json.dumps(self.resources_vlan_create_convert_payload(a_payload)),
                                          a_headers={'content-type': 'application/json'})
                    if r.status_code == 200:
                        return self.resources_vlan_create_convert_result(r.json())
                    else:
                        r.raise_for_status()
                        return "Cannot edit vlan: {0}, {1}".format(r.status_code, r.text)
                else:
                    return "No vlans without name found. Ensure you bought one."
            else:
                return "No vlans found. Ensure you bought one."
        else:
            r.raise_for_status()
            return "Cannot to get list of vlans: {0}, {1}".format(r.status_code, r.text)

    def resources_vlan_info_convert_result(self, a_result):
        """
        @type a_result: dict

        @rtype: unicode
        """
        info = ["type vlan"]

        if key_in(a_result, ['meta']):
            info.append("name {0}".format(a_result['meta']['name']))

        if key_in(a_result, ['uuid']):
            info.append("resource {0}".format(a_result['uuid']))

        if key_in(a_result, ['owner', 'uuid']):
            info.append("user {0}".format(a_result['owner']['uuid']))

        return "\n".join(info)

    def resources_vlan_info(self):
        """
        @rtype: unicode
        """
        r = self.make_request('GET', 'vlans/')

        if r.status_code == 200:
            result = r.json()

            if not key_in(result, ['objects']):
                return "No vlans found. Ensure you bought one."
            else:
                infos = []

                for vlan in result['objects']:
                    r = self.make_request('GET', 'vlans/{0}/'.format(vlan['uuid']))

                    if r.status_code == 200:
                        infos.append(self.resources_vlan_info_convert_result(r.json()))
                    else:
                        r.raise_for_status()

                return "\n\n".join(filter(None, infos))
        else:
            r.raise_for_status()
            return "Cannot get vlans: {0}, {1}".format(r.status_code, r.text)


class TestDrives(unittest.TestCase):
    def test_clone(self):
        c = CloudSigmaLegacy()
        result = c.perform(["drives", "list"]).splitlines()
        self.assertGreater(len(result), 0, "You account MUST have at least 1 test in order to perform this test.")
        result = c.perform(["drives", result[0], "info"]).splitlines()

        for line in result:
            self.assertEqual(line.split(" ", 1), 2, "Each line MUST consist of 2 parts: \"key value\"")

    def test_create(self):
        payload = "name test_5GB\nsize 5368709120"

        pass

    def test_destroy(self):
        pass

    def test_list(self):
        c = CloudSigmaLegacy()
        result = c.perform(["drives", "list"])

    def test_info(self):
        c = CloudSigmaLegacy()
        result = c.perform(["drives", "list"]).splitlines()
        self.assertGreater(len(result), 0, "You account MUST have at least 1 test in order to perform this test.")
        result = c.perform(["drives", result[0], "info"]).splitlines()

        for line in result:
            self.assertEqual(line.split(" ", 1), 2, "Each line MUST consist of 2 parts: \"key value\"")


class TestServers(unittest.TestCase):
    pass


class TestResources(unittest.TestCase):
    pass


if __name__ == '__main__':
    import sys
    from optparse import OptionParser

    parser = OptionParser(usage="usage: %prog [-c | -f FILENAME] [-v] ARGUMENTS",
                          version="%prog {version}".format(version=__version__))

    parser.add_option('-c',
                      action='store_true',
                      dest='stdin',
                      default=False,
                      help="read input data for API call from stdin")

    parser.add_option('-f',
                      type='string',
                      dest='file',
                      help="read input data for API call from FILENAME")

    parser.add_option('-v', '--verbose',
                      action='store_true',
                      dest='verbose',
                      help='Enable verbose mode.')

    options, args = parser.parse_args()

    if len(args) == 0:
        parser.error("you MUST specify arguments")

    if options.stdin and options.file:
        parser.error("options -c and -f are mutually exclusive")

    if options.stdin:
        payload = unicode(sys.stdin.read())
    elif options.file is not None:
        payload = unicode(open(options.file, 'r').read())
    else:
        payload = ""

    c = CloudSigmaLegacy(verbose=options.verbose)

    print(c.perform(args, payload))
