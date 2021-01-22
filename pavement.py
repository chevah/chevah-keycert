"""
Build file for the project.
"""
import os
import re
import sys
from subprocess import call
from pkg_resources import load_entry_point

from paver.easy import call_task, consume_args, task, pushd

EXTRA_PYPI_INDEX = 'https://pypi.chevah.com/simple'


@task
def default():
    call_task('test')


@task
def deps():
    """
    Install all dependencies.
    """
    pip = load_entry_point('pip', 'console_scripts', 'pip')
    pip(args=[
        'install',
        '--extra-index-url', EXTRA_PYPI_INDEX,
        '-e', '.[dev]',
        ])


@task
@consume_args
def test(args):
    """
    Run the test tests.
    """
    import nose

    nose_args = ['nosetests']
    nose_args.extend(args)
    nose_code = nose.run(argv=nose_args)
    nose_code = 0 if nose_code else 1

    sys.exit(nose_code)


@task
@consume_args
def test_interop_load(args):
    """
    Run the SSH key interoperability tests for loading external keys.
    """
    try:
        os.mkdir('build')
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd('build'):
        exit_code = call(
            "../chevah/keycert/tests/ssh_load_keys_tests.sh", shell=True)

    sys.exit(exit_code)

@task
@consume_args
def test_interop_generate(args):
    """
    Run the SSH key interoperability tests for internally-generated keys.
    """
    try:
        os.mkdir('build')
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd('build'):
        exit_code = call(
            "../chevah/keycert/tests/ssh_gen_keys_tests.sh", shell=True)

    sys.exit(exit_code)


@task
def lint():
    """
    Run the static code analyzer.
    """
    from pyflakes.api import main as pyflakes_main
    from pycodestyle import _main as pycodestyle_main

    sys.argv = [
        re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])] + [
        'chevah',
        ]

    try:
        pyflakes_main()
    except SystemExit as pyflakes_exit:
        pass

    sys.argv.extend(['--ignore=E741', '--hang-closing'])
    pycodestyle_exit = pycodestyle_main()

    sys.exit(pyflakes_exit.code or pycodestyle_exit)
