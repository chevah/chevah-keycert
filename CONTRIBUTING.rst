Create issues and send pull requests.

Build development environment and activate it::

    make deps
    . build/venv/bin/activate

Run default tests, linters and coverage::

    python setup.py test

To also get HTML coverage report use::

    make test

Default virtual environment is created in build/venv.

Use nosetests for TDD.
