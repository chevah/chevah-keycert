"""
Demo command line for chevah-keycert.
"""
from __future__ import print_function
# Fix namespaced package import.
import chevah
import os
chevah.__path__.insert(0, os.path.join(os.getcwd(), 'chevah'))

import argparse
import sys
from chevah.keycert.exceptions import KeyCertException
from chevah.keycert.ssh import (
    generate_ssh_key,
    generate_ssh_key_subparser,
    )
from chevah.keycert.ssl import (
    generate_ssl_key_certificate_signing_request,
    generate_ssl_key_certificate_signing_request_subparser,
    )

parser = argparse.ArgumentParser(prog='PROG', prefix_chars='-+')
subparser = parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

sub = generate_ssh_key_subparser(subparser, 'ssh-gen-key')
sub.set_defaults(handler=generate_ssh_key)

sub = generate_ssl_key_certificate_signing_request_subparser(
    subparser, 'ssl-gen-key')
sub.set_defaults(handler=generate_ssl_key_certificate_signing_request)


options = parser.parse_args()

try:
    result = options.handler(options)
    print(result)
except KeyCertException as error:
    print(error)
    sys.exit(1)
