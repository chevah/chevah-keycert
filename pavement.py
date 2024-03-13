"""
Build file for the project.
"""

import os
import sys
import threading
from subprocess import call

from paver.easy import call_task, cmdopts, consume_args, pushd, task
from pkg_resources import load_entry_point

EXTRA_PYPI_INDEX = os.environ["PIP_INDEX_URL"]
BUILD_DIR = os.environ.get("CHEVAH_BUILD", "build-py3")
HAVE_CI = os.environ.get("CI", "false") == "true"
SOURCE_FILES = ["pavement.py", "src"]


def _get_option(options, name, default=None):
    """
    Helper to extract the command line options from paver.
    """
    option_keys = list(options.keys())
    option_keys.remove("dry_run")
    option_keys.remove("pavement_file")
    bunch = options.get(option_keys[0])
    value = bunch.get(name, None)
    if value is None:
        return default

    if value is True:
        return True

    return value.lstrip("=")


@task
def default():
    call_task("test")


@task
def deps():
    """
    Install all dependencies.
    """
    pip = load_entry_point("pip", "console_scripts", "pip")
    pip_args = [
        "install",
        "-U",
        "--extra-index-url",
        EXTRA_PYPI_INDEX,
    ]

    # Install wheel.
    pip(args=pip_args + ["wheel"])

    if not HAVE_CI:
        pip_args.append("-e")

    pip_args.append(".[dev]")
    exit_code = pip(args=pip_args)
    if exit_code:
        raise Exception("Failed to install the deps.")


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
    from chevah_compat.testing import ChevahTestCase
    from chevah_compat.testing.nose_memory_usage import MemoryUsage
    from chevah_compat.testing.nose_run_reporter import RunReporter
    from chevah_compat.testing.nose_test_timer import TestTimer
    from nose.core import main as nose_main
    from nose.plugins.base import Plugin

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
@cmdopts(
    [
        ("load=", "l", "Run key loading tests."),
        ("generate", "g", "Run key generation tests."),
    ]
)
def test_interop(options):
    """
    Run the SSH key interoperability tests.
    """
    environ = os.environ.copy()
    environ["CHEVAH_BUILD"] = BUILD_DIR

    if _get_option(options, "generate"):
        test_command = "ssh_gen_keys_tests.sh"
    else:
        key_type = _get_option(options, "load")
        test_command = "ssh_load_keys_tests.sh {}".format(key_type)

    try:
        os.mkdir(BUILD_DIR)
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd(BUILD_DIR):
        exit_code = call(
            "../src/chevah_keycert/tests/{}".format(test_command),
            shell=True,
            env=environ,
        )

    sys.exit(exit_code)


@task
def lint():
    """
    Run the static code analyzer.
    """
    from black import patched_main
    from isort.main import main as isort_main
    from pyflakes.api import main as pyflakes_main

    try:
        pyflakes_main(args=SOURCE_FILES)
    except SystemExit as error:
        if error.code:
            raise

    exit_code = isort_main(argv=["--check"] + SOURCE_FILES)
    if exit_code:
        raise Exception("isort needs to update the code.")

    sys.argv = ["black", "--check"] + SOURCE_FILES
    exit_code = patched_main()
    if exit_code:
        raise Exception("Black needs to update the code.")


@task
def black():
    """
    Run black on the whole source code.
    """
    from black import patched_main
    from isort.main import main as isort_main

    isort_main(argv=SOURCE_FILES)

    sys.argv = ["black"] + SOURCE_FILES
    patched_main()
