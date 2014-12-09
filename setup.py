from setuptools import setup, find_packages
from codecs import open
from os import path

VERSION = '1.0.1'

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
        'twisted >=12.1.0',
        'pyopenssl ==0.13',
        'pyCrypto ==2.6.1',
        'pyasn1 ==0.1.7',
        'chevah-compat ==0.25.2',
        ],

    extras_require = {
        'dev': [
            'chevah-empirical ==0.31.2',
            'pyflakes ==0.7.3',
            'pocketlint ==1.4.4.c9',
            'nose',
            'mock',
            'bunch',
            ],
        },
    )
