#! /usr/bin/env python
# coding=utf-8

from __future__ import print_function
from __future__ import unicode_literals

__version__ = "1.0"

import json
import requests
import urlparse
from os import environ as os_environ
from os import path

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

DEFAULT_URL_UPLOAD = list(urlparse.urlsplit(DEFAULT_URL))
DEFAULT_URL_UPLOAD[1] = 'direct.' + DEFAULT_URL_UPLOAD[1]
DEFAULT_URL_UPLOAD = urlparse.urlunsplit(DEFAULT_URL_UPLOAD)


def make_request(a_type, a_url, a_endpoint, a_username, a_password, a_data=None, a_params=None, a_headers=None, a_verify=True,
                 a_verbose=False):
    """
    Makes request by setting appropriate url and auth.

    @type a_type: unicode
    @param a_type: Type of the request (GET, PUT, POST or DELETE)

    @type a_endpoint: unicode
    @param a_endpoint: Endpoint for the request.

    @type a_username: unicode
    @param a_username: A username.

    @type a_password: unicode
    @param a_password: A password.

    @type a_data: object
    @param a_data: Request's data

    @type a_params: dict
    @param a_params: Dict representation of additional parameters.
                     E.g. ['do': start'] will be transformed into "?do=start"

    @type a_headers: dict
    @param a_headers: Headers appended to the request.

    @type a_verify: bool
    @param a_verify: Determines whether server's certificate should be verified.

    @type a_verbose: bool
    @param a_verbose: Determines whether verbose info should be printed.

    @rtype: requests.models.Response
    """
    a_type = a_type.lower()
    url = urlparse.urljoin(a_url, a_endpoint)

    if a_verbose:
        print(">>> REQUEST")
        print("\tTYPE:", a_type)
        print("\tURL:", url)

        if a_headers:
            print("\tHEADERS:", a_headers)

        if a_data:
            print("\tDATA:", str(a_data)[:2048])

    if a_type == 'get':
        response = requests.get(url,
                                auth=(a_username, a_password),
                                data=a_data,
                                headers=a_headers,
                                params=a_params,
                                verify=a_verify)
    elif a_type == 'put':
        response = requests.put(url,
                                auth=(a_username, a_password),
                                data=a_data,
                                headers=a_headers,
                                params=a_params,
                                verify=a_verify)
    elif a_type == 'post':
        response = requests.post(url,
                                 auth=(a_username, a_password),
                                 data=a_data,
                                 headers=a_headers,
                                 params=a_params,
                                 verify=a_verify)
    elif a_type == 'delete':
        response = requests.delete(url,
                                   auth=(a_username, a_password),
                                   data=a_data,
                                   headers=a_headers,
                                   params=a_data,
                                   verify=a_verify)
    else:
        raise ValueError("{0} is not supported".format(a_type))

    if a_verbose:
        print("<<< RESPONSE")
        print("\tSTATUS CODE:", response.status_code)
        print("\tHEADERS:", response.headers)
        print("\tDATA:", response.content[:2048])
        print("")

    return response


def upload_drive(a_filepath, a_filename, a_username=DEFAULT_USERNAME, a_password=DEFAULT_PASSWORD, a_verbose=False):
    """
    Uploads file at a_filepath to cloudsigma using a_username and a_password as credentials.
    Then renames it to a_filename.

    @type a_filepath: unicode
    @param a_filepath: Path to the file.

    @type a_filename: unicode
    @param a_filename: Name of the file to be set on server.

    @type a_username: unicode
    @param a_username: A username.

    @type a_password: unicode
    @param a_password: A password.

    @type a_verbose: bool
    @param a_verbose: Determines whether verbose info should be printed.
    """
    with open(a_filepath, 'rb') as f:
        r = make_request('POST', DEFAULT_URL_UPLOAD, 'drives/upload/', a_username, a_password, f,
                         a_headers={'content-type': 'application/octet-stream'},
                         a_verify=False,
                         a_verbose=a_verbose)
        r.raise_for_status()
    uuid = r.text.strip()
    info = get_info(uuid, a_username, a_password, a_verbose)
    update = {'name': a_filename, 'media': info['media'], 'size': info['size']}
    set_info(uuid, update, a_username, a_password, a_verbose)


def get_info(a_uuid, a_username=DEFAULT_USERNAME, a_password=DEFAULT_PASSWORD, a_verbose=False):
    """
    Gets info about drive with a_uuid.

    @type a_uuid: unicode
    @param a_uuid: UUID of the drive.

    @type a_username: unicode
    @param a_username: A username.

    @type a_password: unicode
    @param a_password: A password.

    @type a_verbose: bool
    @param a_verbose: Determines whether verbose info should be printed.

    @rtype: dict
    @return: Returns response in JSON format.
    """
    r = make_request('GET', DEFAULT_URL, 'drives/{0}/'.format(a_uuid), a_username, a_password,
                     a_verbose=a_verbose)
    r.raise_for_status()
    return r.json()


def set_info(a_uuid, a_update, a_username=DEFAULT_USERNAME, a_password=DEFAULT_PASSWORD, a_verbose=False):
    """
    Sets info specified in a_update of the drive with a_uuid.

    @type a_uuid: unicode
    @param a_uuid: UUID of the drive.

    @type a_update: dict
    @param a_update: Updated data to be set on drive (like new name).

    @type a_username: unicode
    @param a_username: A username.

    @type a_password: unicode
    @param a_password: A password.

    @type a_verbose: bool
    @param a_verbose: Determines whether verbose info should be printed.
    """
    r = make_request('PUT', DEFAULT_URL, 'drives/{0}/'.format(a_uuid), a_username, a_password, json.dumps(a_update),
                     a_headers={'content-type': 'application/json'},
                     a_verbose=a_verbose)
    r.raise_for_status()

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser(usage="usage: %prog [-v] FILENAME",
                          version="%prog {version}".format(version=__version__))

    parser.add_option('-v', '--verbose',
                      action='store_true',
                      dest='verbose',
                      help='Enable verbose mode.')

    options, args = parser.parse_args()

    if len(args) == 0:
        parser.error("You MUST specify arguments")

    if not path.isfile(args[0]):
        parser.error("{0} does not point to a valid file".format(args[0]))

    upload_drive(args[0], path.basename(args[0]), DEFAULT_USERNAME, DEFAULT_PASSWORD, options.verbose)
