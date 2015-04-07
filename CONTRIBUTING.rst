Create issues and send pull requests.

All changes need to have tests.
All test code need to have 100% coverage.

Auto-released on PyPi using Travis-CI for each tag.

Build development environment and activate it::

    make deps
    . build/venv/bin/activate

Run checks executed on Travis-CI: test, linters and coverage::

    python setup.py test

To get HTML coverage report use::

    make test

Default virtual environment is created in build/venv.

Use nosetests for TDD.
