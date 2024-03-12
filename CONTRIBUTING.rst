Create issues and send pull requests.

All changes need to have tests.
All test code need to have 100% coverage.

Auto-released on PyPi using Travis-CI for each tag.

Build development environment and activate it.
It uses the chevah-brink script to create the virtual environment ::

    ./pythia.sh deps

Run checks executed on Travis-CI: test, linters and coverage::

    ./pythia.sh test

Default virtual environment is created in build/venv.

Use nosetests for TDD.

You can manually test the command line tools::

    $ ./build/venv/bin/python keycert-demo.py

