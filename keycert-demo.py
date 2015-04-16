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
    generate_ssh_key_parser,
    )
from chevah.keycert.ssl import (
    generate_csr_parser,
    generate_and_store_csr,
    )

parser = argparse.ArgumentParser(prog='PROG', prefix_chars='-+')
subparser = parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

sub = generate_ssh_key_parser(subparser, 'ssh-gen-key')
sub.set_defaults(handler=generate_ssh_key)

sub = generate_csr_parser(subparser, 'ssl-gen-key')
sub.set_defaults(handler=generate_and_store_csr)

options = parser.parse_args()

try:
    options.handler(options)
    print('command succeed')
except KeyCertException as error:
    print(error)
    sys.exit(1)
