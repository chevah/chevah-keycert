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
    Key
    )
from chevah.keycert.ssl import (
    generate_csr_parser,
    generate_and_store_csr,
    generate_ssl_self_signed_certificate,
    )

def ssh_load_key(options, open_method=None):
    """
    Load SSH key from file.

    `options` is an argparse namespace. See `generate_ssh_key_subparser`.

    Return a tuple of (exit_code, operation_message, key).

    For success, exit_code is 0.

    `open_method` is a helper for dependency injection during tests.
    """
    key = None

    if open_method is None:  # pragma: no cover
        open_method = open

    path = options.file

    if not path:
        return (1, 'No path specified', None)

    try:
        with open_method(path, 'rb') as file_handler:
            key = Key.fromString(file_handler.read().strip())
            return (0, 'OK', key)
    except Exception as error:
            return (1, str(error), None)


parser = argparse.ArgumentParser(prog='PROG')
subparser = parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

sub = generate_ssh_key_parser(subparser, 'ssh-gen-key')
sub.set_defaults(handler=generate_ssh_key)

sub = generate_ssh_key_parser(subparser, 'ssh-load-key')
sub.set_defaults(handler=ssh_load_key)

sub = subparser.add_parser(
    'ssh-load-key',
    help='Load an SSH key and show its value.',
    )
sub.add_argument(
    '--file',
    metavar='FILE',
    help='Path the the SSH key to load.'
    )
sub.set_defaults(handler=ssh_load_key)

sub = generate_csr_parser(subparser, 'ssl-gen-key')
sub.set_defaults(handler=generate_and_store_csr)


sub = subparser.add_parser(
    'ssl-self-signed',
    help='Generate a self signed certificate.',
    )
sub.add_argument(
    '--serial',
    type=int,
    default=1234,
    metavar='DECIMAL_NUMBER',
    help='Serial number for the self signed certificate.'
    )
sub.add_argument(
    '--key-size',
    type=int,
    default=1024,
    metavar='BITS',
    help='Size of the newly generated ssl key.'
    )
sub.add_argument(
    '--sign-algorithm',
    default='sha1',
    metavar='STRING',
    help='Algorithm used for the self-signed certificate: sha1, sha256, etc.'
    )
sub.set_defaults(handler=lambda o: print(
    '\n'.join(generate_ssl_self_signed_certificate(o))))

options = parser.parse_args()

try:
    result = options.handler(options)
    print(result)
except KeyCertException as error:
    print(error)
    sys.exit(1)
