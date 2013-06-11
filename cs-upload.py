#! /usr/bin/env python
# coding=utf-8

from __future__ import print_function
from __future__ import unicode_literals

__version__ = "1.0"

import requests
import urlparse
from os import environ as os_environ

# You can override these values by running:
# $ export CSAUTH='user@example.com:password'
USERNAME = 'user@example.com'
PASSWORD = 'password'

# You can override this value by running:
# $ export CSURI='https://zrh.cloudsigma.com/api/2.0/'
URL = 'https://zrh.cloudsigma.com/api/2.0/'

try:
    DEFAULT_USERNAME, DEFAULT_PASSWORD = os_environ['CSAUTH'].split(':')
except:
    DEFAULT_USERNAME, DEFAULT_PASSWORD = USERNAME, PASSWORD


def upload_drive(a_username, a_password, a_filename):
	r = requests.post(urlparse.urljoin(URL, '/api/2.0/drives/upload/'),
    							  auth=(a_username, a_password),
                    files={'file': open(a_filename, 'rb')},
                    headers={'content-type': 'application/octet-stream'})
	r.raise_for_status()
	return r.text


if __name__ == '__main__':
    import sys
    from optparse import OptionParser

    parser = OptionParser(usage="usage: %prog FILENAME",
                          version="%prog {version}".format(version=__version__))

    options, args = parser.parse_args()

    if len(args) == 0:
        parser.error("You MUST specify arguments")

    print(upload_drive(DEFAULT_USERNAME, DEFAULT_PASSWORD, args[0]))
