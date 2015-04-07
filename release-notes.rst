Relese notes for Chevah KeyCert
###############################


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
