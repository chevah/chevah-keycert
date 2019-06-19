Release notes for Chevah KeyCert
################################


2.0.0 - 19/06/2017
==================

* Replace the usage of PyCryto with Python Cryptography.


1.6.0 - 19/06/2017
==================

* Load public SSH keys from X.509 certificates.


1.5.0 - 09/06/2017
==================

* Create CSR with existing private key.
* Create self signed certificate with explicit serial id.


1.4.7 - 13/09/2017
==================

* Update to work with latest pyopenssl where `rand` was removed..


1.4.6 - 13/09/2017
==================

* Remove bogus entry point from setup.py.


1.4.5 - 25/01/2017
==================

* Use latest chevah-compat which includes the testing code.


1.4.4 - 25/01/2017
==================

* Release without changes to test the fix from 1.4.3.


1.4.3 - 25/01/2017
==================

* Fix setup.py to declare the namespace package.


1.4.2 - 06/01/2017
==================

* Add support for SHA1 and SHA256 hash algorithms when getting the
  key's fingerprint.


1.4.1 - 22/08/2016
==================

* Set explicit version when generating the CSR.


1.4.0 - 14/04/2016
==================

* Fails when a passphrase was given for an unencrypted key.
* Fix invalid text in exceptions raised for invalid input.


1.3.5 - 27/04/2015
==================

* Handle all errors when writing files on disk.
* Raise all public errors based on exceptions.KeyCertException


1.3.4 - 20/04/2015
==================

* Update error message for small RSA key size.


1.3.3 - 17/04/2015
==================

* Fall back to sha1 when sha256 is not available on OS to sign CSR.
* Don't allow creating RSA keys less than 512.


1.3.2 - 14/04/2015
==================

* Fix handling of Unicode path on Unix/Linux.
* Remove support for generating SSL DSA keys.
* Rename generate_ssh_key_subparser to generate_ssh_key_parser


1.3.1 - 08/04/2015
==================

* On Unix/Linux ignore sys.getfilesystemencoding() and force a specific
  encoding. UTF-8 by default.


1.3.0 - 07/04/2015
==================

* Add support to generate a SSL key and associated CSR.


1.2.0 - 03/04/2015
==================

* Add helper to populate argparse sub-command for ssh key generation.


1.1.0 - 15/02/2015
==================

* Remove dependency on Twisted
* Raise an error when loading OpenSSH private keys of unknown type (ex ECDSA).
  Previous code was not raising and error and returned `None`.


1.0.1 - 09/12/2014
==================

* Initial test release
