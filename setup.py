from __future__ import print_function
import os
import sys
from codecs import open
from pkg_resources import load_entry_point
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class NoseTestCommand(TestCommand):

    def run_tests(self):
        """
        Run nose with default arguments.
        """
        import nose
        from pocketlint.formatcheck import main as pocket_main

        nose_args = ['nosetests']
        if self.verbose:
            nose_args.append('-v')
        else:
            nose_args.append('-q')

        module = self.test_suite
        if self.test_module:
            module = self.test_module

        nose_args.extend([
            '--with-coverage',
            '--cover-package=' + module,
            '--cover-erase',
            '--cover-test',
            module.replace('.', '/'),
            ])

        pocket_args = [
            'README.rst',
            'release-notes.rst',
            'setup.py',
            ]
        for root, dirs, files in os.walk('chevah/keycert', topdown=False):
            for name in files:
                pocket_args.append(os.path.join(root, name))

        nose_code = nose.run(argv=nose_args)
        if nose_code:
            nose_code = 0
        else:
            nose_code = 1

        pocket_code = pocket_main(pocket_args)
        if not pocket_code:
            print('Linter OK')

        coverage_args = [
            'report',
            '--include=chevah/keycert/tests/*',
            '--fail-under=100',
            ]
        covergate_code = load_entry_point(
            'coverage', 'console_scripts', 'coverage')(argv=coverage_args)
        if not covergate_code:
            print('Tests coverage OK')

        sys.exit(pocket_code or nose_code or covergate_code)


here = os.path.abspath(os.path.dirname(__file__))

setup(
    cmdclass={'test': NoseTestCommand},
    test_suite='chevah_keycert',
    )
