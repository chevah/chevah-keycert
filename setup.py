import sys
from codecs import open
from os import path
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

VERSION = '1.0.1'


class NoseTestCommand(TestCommand):

    def run_tests(self):
        """
        Run nose with default arguments.
        """
        import nose
        from pocketlint.formatcheck import main as pocket_main

        module = 'chevah.keycert'
        nose_args = ['nosetests']
        if self.verbose:
            nose_args.append('-v')
        else:
            nose_args.append('-q')

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
            'chevah/keycert',
            'README.rst',
            'setup.py',
            ]

        nose_code = nose.run(argv=nose_args)
        if nose_code:
            nose_code = 0
        else:
            nose_code = 1

        pocket_code = pocket_main(pocket_args)
        sys.exit(pocket_code or nose_code)


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='chevah-keycert',

    version=VERSION,

    description='SSH Keys and SSL keys and certificates management.',
    long_description=long_description,

    url='https://github.com/chevah/chevah-keycert',

    author='Adi Roiban',
    author_email='adiroiban@gmail.com',

    license='MIT',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        ],

    keywords='twisted ssh ssl tls pki ca',

    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),

    install_requires=[
        'pyopenssl ==0.13',
        'pyCrypto ==2.6.1',
        'pyasn1 ==0.1.7',
        'chevah-compat ==0.27.0',
        ],

    extras_require={
        'dev': [
            'chevah-empirical ==0.33.0',
            'pyflakes ==0.8.1',
            'pocketlint ==1.4.4.c10',
            'pep8 ==1.6.1',
            'nose',
            'mock',
            'bunch',
            'coverage',
            'coveralls',
            ],
        },
    cmdclass={'test': NoseTestCommand},
    test_suite='chevah.keycert.tests',
    )
