Release notes for Chevah KeyCert
################################

3.1.0 - 2024-03-23
==================

* Remove support for py2
* Remove support for LSH
* Add support for Putty key gen3
* Update automated tests


3.0.12 - 2024-01-27
===================

* Update to support pyOpenSSL 24.0.0.


3.0.11 - 2023-07-29
===================

* No longer ask for compat and scandir as they are only needed for testing.


3.0.10 - 2023-07-04
==================

* Update for cryptography 39 and newer.


3.0.9 - 2023-05-22
==================

* Handle already encoded paths on Linux.


3.0.8 - 2023-05-03
==================

* SSH.com and Putty string serialization is done to bytes.


3.0.7 - 2023-04-28
==================

* Fix generating and reading Putty v2 keys.


3.0.6 - 2023-04-24
==================

* Get SSH.com and Putty ssh key handling working on py3.


3.0.5 - 2023-04-01
==================

* Get CSR generation working on py2 and py3.


3.0.4 - 2023-04-01
==================

* More fixes for CSR generation.


3.0.3 - 2023-03-27
==================

* Fix ssl.py CSR and cert generation on Py3.


3.0.2 - 2023-03-24
==================

* Improve py2 and py3 support.


3.0.1 - 2023-03-22
==================

* Have exception str() return text, not bytes.


3.0.0 - 2023-03-21
==================

* Get py3 code and move into a non-namespace package.


2.1.2 - 2023-03-01
==================

* Just an update to test our internal pypi server.


2.1.1 - 2023-02-01
==================

* In errors enclose input values in quotes.


2.1.0 - 2023-02-01
==================

* Add support for rsa-sha2-256 and rsa-sha2-512.


2.0.6 - 2021-02-05
==================

* Raise a dedicated error when ED keys are not supported.


2.0.5 - 2021-02-03
==================

* SSH.com private key is experted as bytes.


2.0.4 - 2021-01-26
==================

* Don't add a comment for non OpenSSH public keys as comment is not yet
  supported for those formats.
* Make sure all errors have valid unicode text.
* Raise a custom exception when trying to sign using a public key.


2.0.3 - 2021-01-22
==================

* Show an error when loading DSA keys with unsupported sizes.
  It was not fixed in 2.0.2.


2.0.2 - 2021-01-21
==================

* Show an error when loading DSA keys with unsupported sizes.


2.0.1 - 2021-01-12
==================

* Add ECDSA/ED support for PKCS#8 format.


2.0.0 - 2021-01-05
==================

* Initial migration to cryptography.
* Add support for ECDSA and ED25519.
* SSH.com file format only support RSA and DSA key for now.


1.12.5 - 2020-07-20
===================

* Set version 3 to CSR and self signed certificates, as only version 3 can
  have extensions.


1.12.5 - 2020-07-10
===================

* Untracked change.


1.12.4 - 2020-07-10
===================

* Add better error messages for invalid sign algorithm.


1.12.4 - 2020-07-10
===================

* Add better error messages for invalid country code and email address.


1.12.3 - 2020-07-09
===================

* Fix unicode handling for certificate signature.


1.12.2 - 2020-07-09
===================

* Update command line help messages.


1.12.1 - 2020-07-06
===================

* Allow defining key usage and constraints for Certificate Signing Requests
  and self-signed certificates.


1.12.0 - 2020-07-06
===================

* Allow creating self-signed certificates with custom attributes.


1.11.1 - 2020-07-02
===================

* Load OpenSSH v1 private keys without any padding checks.
* Add support for PKCS#1 RSA public key PEM format.


1.11.0 - 2020-06-29
===================

* Add support for unencrypted RSA and DSA OpenSSH v1 private keys.


1.10.0 - 2020-05-12
===================

* Add support for configurable key size and signing algorithm when creating
  a self signed certificate.


1.9.3 - 2019-10-24
==================

* Remove interactive password input for encrypted PKCS#8 files.


1.9.2 - 2019-10-24
==================

* Fix syntax error bug.


1.9.1 - 2019-10-24
==================

* Add support for SSH get key type for PKCS#8 and PKCS#1.


1.9.0 - 2019-10-21
==================

* Load SSH keys from PKCS#8 private key PEM files (RSA and DSA).


1.8.0 - 2019-10-16
==================

* Load SSH keys from PKCS#1 private key PEM files (RSA and DSA).


1.7.0 - 2019-10-16
==================

* Load public SSH keys from PKCS#1 public key PEM files (RSA and DSA).


1.6.0 - 19/06/2019
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
