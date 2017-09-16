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
        'twisted', 'buildbot==0.8.11rc8', 'service_identity',
        ])


@task
def test():
    """
    Run the test tests.
    """
    import nose

    coverage = load_entry_point('coverage', 'console_scripts', 'coverage')

    nose_args = ['nosetests']
    nose_args.extend([
        '--with-coverage',
        '--cover-package=chevah.keycert',
        '--cover-erase',
        '--cover-test',
        ])
    nose_code = nose.run(argv=nose_args)
    nose_code = 0 if nose_code else 1

    coverage_args = [
        'report',
        '--include=chevah/keycert/tests/*',
        '--fail-under=100',
        ]
    covergate_exit = coverage(argv=coverage_args)
    if not covergate_exit:
        print('Tests coverage OK')

    coverage(argv=['html', '-d', 'build/cover'])
    print("See HTML coverate in build/cover")

    sys.exit(nose_code or covergate_exit)


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


@task
@consume_args
def remote(args):
    """
    Trigger tests on Builbot CI.
    """
    from buildbot.scripts import runner
    from io import BytesIO
    base_args = [
        'buildbot',
        'try',
        '--connect=pb',
        '--username=chevah_buildbot',
        '--passwd=chevah_password',
        '--master=build.chevah.com:10087',
        '--vc=git',
        ]
    out = BytesIO()
    if not args:
        sys.argv = base_args + ['--get-builder-names']
        sys.stdout = out
    else:
        sys.argv = base_args + args

    try:
        runner.run()
    except SystemExit as buildbot_exit:
        pass

    for line in out.getvalue().splitlines():
        if 'brink' in line:
            print(line)

    sys.exit(buildbot_exit)

    # BUILDBOT_TRY=$(BASE_PATH)/buildbot try \
    #         --connect=pb --username=chevah_buildbot --passwd=chevah_password \
    #         --master=build.chevah.com:10087 --vc=git
    # test_remote: git_push
    # ifeq "$(TARGET)" ""
    #     $(BUILDBOT_TRY) --get-builder-names | grep keycert
    # else
    #     $(BUILDBOT_TRY) -b $(TARGET)
    # endif

    # test_remote_with_purge: git_push
    #     $(BUILDBOT_TRY) -b $(TARGET) --properties=force_purge=yes

    # test_remote_with_wait: git_push
    #     $(BUILDBOT_TRY) -b $(TARGET) --wait
