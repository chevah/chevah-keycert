"""
Build file for the project.
"""

from importlib.metadata import entry_points
import os
import sys
import threading
from subprocess import call

from paver.easy import call_task, cmdopts, consume_args, pushd, task

EXTRA_PYPI_INDEX = os.environ["PIP_INDEX_URL"]
BUILD_DIR = os.environ.get("CHEVAH_BUILD", "build")
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
def build():
    """
    Here to make pythia.sh happy.

    Project is built via deps.
    """


@task
def deps():
    """
    Install all dependencies.
    """
    pip_entry_point = entry_points(group="console_scripts", name="pip")["pip"]
    pip = pip_entry_point.load()
    pip_args = [
        "install",
        "--extra-index-url",
        EXTRA_PYPI_INDEX,
    ]

    # Install wheel.
    pip(args=pip_args)

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
        ChevahTestCase.setupPrivileges()
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
        ("load=", "l", "Run key loading tests. Ex: '-l ecdsa'."),
        ("generate=", "g", "Run key generation tests. Ex: -g ' ', to run all"),
    ]
)
def test_interop(options):
    """
    Run the SSH key interoperability tests.

    This is the helper for our automated tests.
    """
    environ = os.environ.copy()
    environ["CHEVAH_BUILD"] = BUILD_DIR

    generate_option = _get_option(options, "generate")
    key_type = _get_option(options, "load")
    if generate_option:
        test_command = "ssh_gen_keys_tests.sh {}".format(generate_option)
    else:
        test_command = "ssh_load_keys_tests.sh {}".format(key_type)

    try:
        os.mkdir(BUILD_DIR)
    except OSError:
        """Already exists"""

    exit_code = 1
    with pushd(BUILD_DIR):
        print("Testing: {}".format(test_command))
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


@task
@consume_args
def ruff(args):
    """
    Run the static code analyzer.
    """
    ruff = os.path.join(BUILD_DIR, "bin", "ruff")
    ruff_args = ['check']  + (args or SOURCE_FILES)
    exit_code = call([ruff] + ruff_args)
    if exit_code:
        raise Exception("Ruff checks failed.")

