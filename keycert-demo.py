"""
Demo command line for chevah-keycert.

Usage:

* ssh-gen-key - Generate key, various formats, with or without password.
* ssh-load-key  - Load key, various formats, with or without password.

"""
from __future__ import print_function, unicode_literals
# Fix namespaced package import.
import chevah
import os
import sys
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
    generate_self_signed_parser,
    generate_ssl_self_signed_certificate,
    )


def print_error(*args, **kwargs):
    """
    Print to standard error.
    """
    print(*args, file=sys.stderr, **kwargs)


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
    output_format = options.type
    password = options.password

    if not path:
        return (1, 'No path specified', None)

    with open_method(path, 'rb') as file_handler:
        key_content = file_handler.read().strip()
        key = Key.fromString(key_content, passphrase=password)

        if key.isPublic():
            to_string = key.toString(output_format)
        else:
            to_string = key.toString(output_format)

        result = '%r\nKey type %s\n\n%s' % (
            key,
            Key.getKeyFormat(key_content),
            to_string,
            )
        return result

def ssh_sign_data(options):
    """
    Sign data with SSH private key.
    """
    key = None

    path = options.file
    data = options.data

    if not path:
        return (1, 'No path specified', None)

    with open(path, 'rb') as file_handler:
        key_content = file_handler.read().strip()
        key = Key.fromString(key_content)
        if key.isPublic():
            raise AssertionError('A private key must be used.')

        return key.sign(
            data.encode('utf-8')).encode('base64').replace('\n', '')


def ssh_verify_data(options):
    """
    Verify data with SSH public key.
    """
    key = None

    path = options.file
    signature = options.signature
    data = options.data

    if not path:
        return (1, 'No path specified', None)

    with open(path, 'rb') as file_handler:
        key_content = file_handler.read().strip()
        key = Key.fromString(key_content)

        if not key.verify(
                signature.decode('base64'), data.encode('utf-8')):
            return 'INVALID Signature'

        return 'VALID Signature'


parser = argparse.ArgumentParser(prog='PROG')
subparser = parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

sub = generate_ssh_key_parser(subparser, 'ssh-gen-key')
sub.set_defaults(handler=generate_ssh_key)


sub = subparser.add_parser(
    'ssh-load-key',
    help='Load an SSH key and show its value.',
    )
sub.add_argument(
    '--file',
    metavar='FILE',
    help='Path the the SSH key to load.'
    )
sub.add_argument(
    '--type',
    metavar='[openssh|openssh_v1|putty|sshcom]',
    default='openssh_v1',
    help='Format use to show the loaded key.'
    )
sub.add_argument(
    '--password',
    metavar='PASSWORD',
    default=None,
    help='Option password or commented used when re-encoding the loaded key.'
    )
sub.set_defaults(handler=ssh_load_key)


sub = subparser.add_parser(
    'ssh-sign-data',
    help='Sign data using SSH private key.',
    )
sub.add_argument(
    '--file',
    metavar='FILE',
    help='Path the the SSH private key to use.'
    )
sub.add_argument(
    '--data',
    metavar='PLAIN-DATA',
    default='test-value',
    help='Data that is signed.'
    )
sub.set_defaults(handler=ssh_sign_data)

sub = subparser.add_parser(
    'ssh-verify-data',
    help='Verify data using SSH public key.',
    )
sub.add_argument(
    '--file',
    metavar='FILE',
    help='Path the the SSH public key to load.'
    )
sub.add_argument(
    '--signature',
    metavar='BASE64',
    default='',
    help='Signed data to be verified.'
    )
sub.add_argument(
    '--data',
    metavar='PLAIN-DATA',
    default='test-value',
    help='Data for which the signature is verified.'
    )
sub.set_defaults(handler=ssh_verify_data)


sub = generate_csr_parser(subparser, 'ssl-csr')
sub.set_defaults(handler=lambda o: (
    generate_and_store_csr(o)
    or print('CSR generated in files.')
    or ''
    ))

sub = generate_self_signed_parser(subparser, 'ssl-self-signed')
sub.set_defaults(handler=lambda o:
    b'\n'.join(generate_ssl_self_signed_certificate(o)))

options = parser.parse_args()

try:
    result = options.handler(options)
    print(result)
except KeyCertException as error:
    print_error('EXPECTED ERROR')
    print_error(error)
    sys.exit(1)
except Exception as error:
    print_error('UNEXPECTED ERROR. A bug should be reported.',)
    print_error(error)
    sys.exit(2)
