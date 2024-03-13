"""
Build file for the project.
"""

import os
import re
import sys
import threading
from subprocess import call
from pkg_resources import load_entry_point

from paver.easy import call_task, consume_args, task, pushd

EXTRA_PYPI_INDEX = os.environ["PIP_INDEX_URL"]
BUILD_DIR = os.environ.get("CHEVAH_BUILD", "build-py3")


@task
def default():
    call_task("test")


@task
def deps():
    """
    Install all dependencies.
    """
    pip = load_entry_point("pip", "console_scripts", "pip")
    exit_code = pip(
        args=[
            "install",
            "-U",
            "--extra-index-url",
            EXTRA_PYPI_INDEX,
            "-e",
            ".[dev]",
        ]
    )
    if exit_code:
        raise Exception('Failed to install the deps.')


@task
@consume_args
def test(args):
    """
    Run the test tests.
    """
    _nose(args, cov=None)


def _nose(args, cov, base="chevah_keycert.tests"):
    """
    Run nose tests in the same process.
    """
    # Delay import after coverage is started.
    import psutil
    from nose.core import main as nose_main
    from nose.plugins.base import Plugin
    from chevah_compat.testing import ChevahTestCase

    from chevah_compat.testing.nose_memory_usage import MemoryUsage
    from chevah_compat.testing.nose_test_timer import TestTimer
    from chevah_compat.testing.nose_run_reporter import RunReporter

    import chevah_keycert

    class LoopPlugin(Plugin):
        name = "loop"

    new_arguments = [
        "--with-randomly",
        "--with-run-reporter",
        "--with-timer",
        "-v",
        "-s",
    ]

    have_tests = False
    for argument in args:
        if not argument.startswith("-"):
            argument = "%s.%s" % (base, argument)
            have_tests = True
        new_arguments.append(argument)

    if not have_tests:
        # Run all base tests if no specific tests was requested.
        new_arguments.append(base)

    sys.argv = new_arguments
    print(new_arguments)

    plugins = [TestTimer(), RunReporter(), MemoryUsage(), LoopPlugin()]

    with pushd(BUILD_DIR):
        ChevahTestCase.initialize(drop_user="-")
        ChevahTestCase.dropPrivileges()
        try:
            nose_main(addplugins=plugins)
        finally:
            process = psutil.Process(os.getpid())
            print("Max RSS: {} MB".format(process.memory_info().rss / 1000000))
            if cov:
                cov.stop()
                cov.save()
            threads = threading.enumerate()
            if len(threads) > 1:
                print("There are still active threads: %s" % threads)
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(1)


@task
@consume_args
def test_interop_load_dsa(args):
    """
    Run the SSH key interoperability tests for loading external DSA keys.
    """
    try:
        os.mkdir("build")
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd("build"):
        exit_code = call(
            "../src/chevah_keycert/tests/ssh_load_keys_tests.sh dsa", shell=True
        )

    sys.exit(exit_code)


@task
@consume_args
def test_interop_load_rsa(args):
    """
    Run the SSH key interoperability tests for loading external RSA keys.
    """
    try:
        os.mkdir("build")
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd("build"):
        exit_code = call(
            "../src/chevah_keycert/tests/ssh_load_keys_tests.sh rsa", shell=True
        )

    sys.exit(exit_code)


@task
@consume_args
def test_interop_load_eced(args):
    """
    Run the SSH key interoperability tests for loading external ECDSA and Ed25519 keys.
    """
    try:
        os.mkdir("build")
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd("build"):
        exit_code = call(
            "../src/chevah_keycert/tests/ssh_load_keys_tests.sh ecdsa ed25519",
            shell=True,
        )

    sys.exit(exit_code)


@task
@consume_args
def test_interop_generate(args):
    """
    Run the SSH key interoperability tests for internally-generated keys.
    """
    try:
        os.mkdir("build")
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd("build"):
        exit_code = call(
            "../stc/chevah_keycert/tests/ssh_gen_keys_tests.sh", shell=True
        )

    sys.exit(exit_code)


@task
def lint():
    """
    Run the static code analyzer.
    """
    from pyflakes.api import main as pyflakes_main
    from pycodestyle import _main as pycodestyle_main
    from black import patched_main

    try:
        pyflakes_main(args=['src/chevah_keycert'])
    except SystemExit as error:
        if error.code:
            raise

    sys.argv = ['black', '--check', 'src']
    sys.exit(patched_main())


@task
def black():
    """
    Run black on the whole source code.
    """
    from black import patched_main
    sys.argv = ['black', 'src']
    sys.exit(patched_main())
