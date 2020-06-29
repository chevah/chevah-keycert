"""
Build file for the project.
"""
import os
import re
import sys
from pkg_resources import load_entry_point

from paver.easy import call_task, consume_args, task

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
def test():
    """
    Run the test tests.
    """
    import nose

    nose_args = ['nosetests']
    nose_args.extend([
        ])
    nose_code = nose.run(argv=nose_args)
    nose_code = 0 if nose_code else 1

    sys.exit(nose_code)


@task
def test_ci():
    """
    Run tests in the Buildbot CI environment.
    """
    test_type = os.environ.get('TEST_TYPE', '')
    if test_type == "os-independent":
        call_task('lint')
    else:
        call_task('test')



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
