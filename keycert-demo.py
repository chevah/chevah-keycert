"""
Demo command line for chevah-keycert.
"""
# Fix namespaced package import.
import chevah
import os
chevah.__path__.insert(0, os.path.join(os.getcwd(), 'chevah'))

import argparse
import sys
from chevah.keycert.ssh import (
    generate_ssh_key,
    generate_ssh_key_subparser,
    )

parser = argparse.ArgumentParser(prog='PROG', prefix_chars='-+')
subparser = parser.add_subparsers(
            help='Available sub-commands', dest='sub_command')

generate_ssh_key_subparser(subparser, 'gen-ssh-key')

options = parser.parse_args()
if options.sub_command == 'gen-ssh-key':
    exit, message, _ = generate_ssh_key(options)
    sys.stdout.write(message)
    sys.exit(exit)
