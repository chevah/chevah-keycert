Create issues and send pull requests.

All changes need to have tests.
All test code need to have 100% coverage.

Auto-released on PyPi using Travis-CI for each tag.

Build development environment and activate it.
It uses the chevah-brink script to create the virtual environment ::

    ./brink.sh deps

Run checks executed on Travis-CI: test, linters and coverage::

    ./brink.sh test

Default virtual environment is created in build/venv.

Use nosetests for TDD.

Linux, OS X and Windows tests executed on private buildbot server as Travis CI
is Linux only::

    # See available builders
    ./brink.sh remote
    # Trigger a builder
    ./brink.sh remote [--wait] -b keycert-win-2008
    # Trigger a builder with running the clean step
    ./brink.sh remote -b keycert-win-2008 --properties=force_purge=yes
