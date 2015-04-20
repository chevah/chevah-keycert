#!/usr/bin/env bash
# Copyright (c) 2010-2013 Adi Roiban.
# See LICENSE for details.
#
# Helper script for bootstraping the build system on Unix/Msys.
# It will write the default values into 'DEFAULT_VALUES' file.
#
# To use this script you will need to publish binary archive files for the
# following components:
#
# * Python main distribution
# * pip
# * setuptools
#
# It will delegate the argument to the paver script, with the exception of
# these commands:
# * clean - remove everything, except cache
# * detect_os - create DEFAULT_VALUES and exit
# * get_python - download Python distribution in cache
# * get_agent - download Rexx/Putty distribution in cache
#

# Script initialization.
set -o nounset
set -o errexit
set -o pipefail

# Initialize default value.
COMMAND=${1-''}
DEBUG=${DEBUG-0}

# Set default locale.
# We use C (alias for POSIX) for having a basic default value and
# to make sure we explictly convert all unicode values.
export LANG='C'
export LANGUAGE='C'
export LC_ALL='C'
export LC_CTYPE='C'
export LC_COLLATE='C'
export LC_MESSAGES='C'
export PATH=$PATH:'/sbin:/usr/sbin:/usr/local/bin:/opt/csw/bin/'

#
# Global variables.
#
# Used to return non-scalar value from functions.
RESULT=''
WAS_PYTHON_JUST_INSTALLED=0
DIST_FOLDER='dist'

# Path global variables.
BUILD_FOLDER="build"
CACHE_FOLDER="cache"
PYTHON_BIN=""
PYTHON_LIB=""
LOCAL_PYTHON_BINARY_DIST=""
CLEAN_PYTHON_BINARY_DIST_CACHE=""
BINARY_DIST_URI='http://chevah.com/binary'
PIP_INDEX='http://chevah.com/pypi'
PYTHON_VERSION="python2.7"

# Load repo specific configuration.
if [ -e paver.conf ]; then
    source paver.conf
fi


# Put default values and create them as global variables.
OS='not-detected-yet'
ARCH='x86'


clean_build() {
    # Shortcut for clear since otherwise it will depend on python
    echo "Removing ${BUILD_FOLDER}..."
    delete_folder ${BUILD_FOLDER}
    echo "Removing dist..."
    delete_folder ${DIST_FOLDER}
    echo "Removing publish..."
    delete_folder 'publish'
    echo "Cleaning project temporary files..."
    rm -f DEFAULT_VALUES
    echo "Cleaning pyc files ..."
    if [ $OS = "rhel4" ]; then
        # RHEL 4 don't support + option in -exec
        # We use -print0 and xargs to no fork for each file.
        # find will fail if no file is found.
        touch ./dummy_file_for_RHEL4.pyc
        find ./ -name '*.pyc' -print0 | xargs -0 rm
    else
        # AIX's find complains if there are no matching files when using +.
        [ $(uname) == AIX ] && touch ./dummy_file_for_AIX.pyc
        # Faster than '-exec rm {} \;' and supported in most OS'es,
        # details at http://www.in-ulm.de/~mascheck/various/find/#xargs
        find ./ -name '*.pyc' -exec rm {} +
    fi
    # In some case pip hangs with a build folder in temp and
    # will not continue until it is manually removed.
    rm -rf /tmp/pip*

    if [ "$CLEAN_PYTHON_BINARY_DIST_CACHE" = "yes" ]; then
        echo "Cleaning python binary ..."
        rm -rf cache/python*
    fi
}


#
# Delete the folder as quickly as possible.
#
delete_folder() {
    local target="$1"
    # On Windows, we use internal command prompt for maximum speed.
    # See: http://stackoverflow.com/a/6208144/539264
    if [ $OS = "windows" -a -d $target ]; then
        cmd //c "del /f/s/q $target > nul"
        cmd //c "rmdir /s/q $target"
    else
        rm -rf $target
    fi
}


#
# Wrapper for executing a command and exiting on failure.
#
execute() {
    if [ $DEBUG -ne 0 ]; then
        echo "Executing:" $@
    fi

    #Make sure $@ is called in quotes as otherwise it will not work.
    set +e
    "$@"
    exit_code=$?
    set -e
    if [ $exit_code -ne 0 ]; then
        echo "Fail:" $@
        exit 1
    fi
}

#
# Update global variables with current paths.
#
update_path_variables() {

    if [ "${OS}" = "windows" ] ; then
        PYTHON_BIN="/lib/python.exe"
        PYTHON_LIB="/lib/Lib/"
    else
        PYTHON_BIN="/bin/python"
        PYTHON_LIB="/lib/${PYTHON_VERSION}/"
    fi

    PYTHON_BIN="${BUILD_FOLDER}${PYTHON_BIN}"
    PYTHON_LIB="${BUILD_FOLDER}${PYTHON_LIB}"

    LOCAL_PYTHON_BINARY_DIST="$PYTHON_VERSION-$OS-$ARCH"

    export PYTHONPATH=${BUILD_FOLDER}
}



#
# Download a tar.gz archive and extract it in current folder.
#
get_tar_tz() {
    local dist_name=$1
    local remote_url=$2

    echo "Getting $dist_name from $remote_url..."

    tar_gz_file=${dist_name}.tar.gz
    tar_file=${dist_name}.tar

    # Get and extract archive.
    rm -rf $dist_name
    rm -f $tar_gz_file
    rm -f $tar_file
    # Use 1M dot to reduce console pollution.
    execute wget --progress=dot -e dotbytes=1M $remote_url/${tar_gz_file}
    execute gunzip $tar_gz_file
    execute tar -xf $tar_file
    rm -f $tar_gz_file
    rm -f $tar_file
}


#
# Make sure a python environment is available at path.
#
distributable_python() {

    PIP_VERSION="6.1.1"
    SETUPTOOLS_VERSION="15.0"

    local destination=$1

    local python_distributable="${CACHE_FOLDER}/${PYTHON_VERSION}-${OS}-${ARCH}"
    local pip_package="pip-$PIP_VERSION"

    if [ "${OS}" = "windows" ] ; then
        local python_bin="python.exe"
        local venv_path=${PYTHON_VERSION}-${OS}-${ARCH}/lib
    else
        local python_bin="bin/python"
        local venv_path=${PYTHON_VERSION}-${OS}-${ARCH}
    fi

    # Check that python dist was installed
    if [ -s $destination/$python_bin ]; then
        return 0
    fi

    get_tar_tz ${PYTHON_VERSION}-${OS}-${ARCH} "$BINARY_DIST_URI/python"
    echo "Bootstraping ${PYTHON_VERSION} environment to $destination..."
    # Our Windows python-package has the venv in lib folder.
    mv ${venv_path} $destination
    rm -rf ${PYTHON_VERSION}-${OS}-${ARCH}

    pushd $destination

        execute wget \
            --no-check-certificate https://bootstrap.pypa.io/ez_setup.py \
            -O ez_setup.py
        execute $python_bin ez_setup.py

        execute wget --no-check-certificate https://bootstrap.pypa.io/get-pip.py
        execute $python_bin get-pip.py \
            --index-url=http://chevah.com/pypi/simple/ \
            --trusted-host=chevah.com
    popd
}


#
# Check version of current OS to see if it is supported.
# If it's too old, exit with a nice informative message.
# If it's supported, return through eval the version numbers to be used for
# naming the package, for example '5' for RHEL 5.x, '1204' for Ubuntu 12.04',
# '53' for AIX 5.3.x.x , '10' for Solaris 10 or '1010' for OS X 10.10.1.
#
check_os_version() {
    # First parameter should be the human-readable name for the current OS.
    # For example: "Red Hat Enterprise Linux" for RHEL, "OS X" for Darwin etc.
    # Second and third parameters must be strings composed of integers
    # delimited with dots, representing, in order, the oldest version
    # supported for the current OS and the current detected version.
    # The fourth parameter is used to return through eval the relevant numbers
    # for naming the Python package for the current OS, as detailed above.
    local name_fancy="$1"
    local version_good="$2"
    local version_raw="$3"
    local version_chevah="$4"
    local version_constructed=''
    local flag_supported='good_enough'
    local version_raw_array
    local version_good_array

    # Using '.' as a delimiter, populate the version_raw_* arrays.
    IFS=. read -a version_raw_array <<< "$version_raw"
    IFS=. read -a version_good_array <<< "$version_good"

    # Iterate through all the integers from the good version to compare them
    # one by one with the corresponding integers from the supported version.
    for (( i=0 ; i < ${#version_good_array[@]}; i++ )); do
        version_constructed="${version_constructed}${version_raw_array[$i]}"
        if [ ${version_raw_array[$i]} -gt ${version_good_array[$i]} -a \
            "$flag_supported" = 'good_enough' ]; then
            flag_supported='true'
        elif [  ${version_raw_array[$i]} -lt ${version_good_array[$i]} -a \
            "$flag_supported" = 'good_enough' ]; then
            flag_supported='false'
        fi
    done

    if [ "$flag_supported" = 'false' ]; then
        echo "The current version of ${name_fancy} is too old: ${version_raw}"
        echo "Oldest supported version of ${name_fancy} is: ${version_good}"
        exit 13
    fi

    # The sane way to return fancy values with a bash function is to use eval.
    eval $version_chevah="'$version_constructed'"
}


#
# Update OS and ARCH variables with the current values.
#
detect_os() {

    OS=$(uname -s | tr "[A-Z]" "[a-z]")

    if [ "${OS%mingw*}" = "" ]; then

        OS='windows'
        ARCH='x86'

    elif [ "${OS}" = "sunos" ]; then

        ARCH=$(isainfo -n)
        os_version_raw=$(uname -r | cut -d'.' -f2)
        check_os_version Solaris 10 "$os_version_raw" os_version_chevah

        OS="solaris${os_version_chevah}"

    elif [ "${OS}" = "aix" ]; then

        ARCH="ppc$(getconf HARDWARE_BITMODE)"
        os_version_raw=$(oslevel)
        check_os_version AIX 5.3 "$os_version_raw" os_version_chevah

        OS="aix${os_version_chevah}"

    elif [ "${OS}" = "hp-ux" ]; then

        ARCH=$(uname -m)
        os_version_raw=$(uname -r | cut -d'.' -f2-)
        check_os_version HP-UX 11.31 "$os_version_raw" os_version_chevah

        OS="hpux${os_version_chevah}"

    elif [ "${OS}" = "linux" ]; then

        ARCH=$(uname -m)

        if [ -f /etc/redhat-release ]; then
            # Avoid getting confused by Red Hat derivatives such as Fedora.
            egrep 'Red\ Hat|CentOS|Scientific' /etc/redhat-release > /dev/null
            if [ $? -eq 0 ]; then
                os_version_raw=$(\
                    cat /etc/redhat-release | sed s/.*release// | cut -d' ' -f2)
                check_os_version "Red Hat Enterprise Linux" 4 \
                    "$os_version_raw" os_version_chevah
                OS="rhel${os_version_chevah}"
            fi
        elif [ -f /etc/SuSE-release ]; then
            # Avoid getting confused by SUSE derivatives such as OpenSUSE.
            if [ $(head -n1 /etc/SuSE-release | cut -d' ' -f1) = 'SUSE' ]; then
                os_version_raw=$(\
                    grep VERSION /etc/SuSE-release | cut -d' ' -f3)
                check_os_version "SUSE Linux Enterprise Server" 11 \
                    "$os_version_raw" os_version_chevah
                OS="sles${os_version_chevah}"
            fi
        elif [ $(command -v lsb_release) ]; then
            lsb_release_id=$(lsb_release -is)
            os_version_raw=$(lsb_release -rs)
            if [ $lsb_release_id = Ubuntu ]; then
                check_os_version "Ubuntu Long-term Support" 10.04 \
                    "$os_version_raw" os_version_chevah
                # Only Long-term Support versions are oficially endorsed, thus
                # $os_version_chevah should end in 04 and the first two digits
                # should represent an even year.
                if [ ${os_version_chevah%%04} != ${os_version_chevah} -a \
                    $(( ${os_version_chevah%%04} % 2 )) -eq 0 ]; then
                    OS="ubuntu${os_version_chevah}"
                fi
            fi
        fi

    elif [ "${OS}" = "darwin" ]; then
        ARCH=$(uname -m)

        os_version_raw=$(sw_vers -productVersion)
        check_os_version "Mac OS X" 10.4 "$os_version_raw" os_version_chevah

        # For now, no matter the actual OS X version returned, we use '108'.
        OS="osx108"

    else
        echo 'Unsupported operating system:' $OS
        exit 14
    fi

    # Fix arch names.
    if [ "$ARCH" = "i686" -o "$ARCH" = "i386" ]; then
        ARCH='x86'
    elif [ "$ARCH" = "x86_64" -o "$ARCH" = "amd64" ]; then
        ARCH='x64'
    elif [ "$ARCH" = "sparcv9" ]; then
        ARCH='sparc64'
    elif [ "$ARCH" = "ppc64" ]; then
        # Python has not been fully tested on AIX when compiled as a 64 bit
        # application and has math rounding error problems (at least with XL C).
        ARCH='ppc'
    elif [ "$ARCH" = "aarch64" ]; then
        ARCH='arm64'
    fi
}

detect_os
update_path_variables

if [ "$OS" = "ubuntu1204" -a "$ARCH" = "x86" ]; then
    OS='linux'
fi

case $OS in
    solaris*|aix*|hpux*)
        MAKE=gmake
        ;;
    *)
        MAKE=make
        ;;
esac


if [ "$COMMAND" = "clean" ] ; then
    clean_build
    exit 0
fi

if [ "$COMMAND" = "ci_deps" ] ; then
    $MAKE ci_deps
    exit $?
fi

if [ "$COMMAND" = "ci_test" ] ; then
    $MAKE ci_test
    exit $?
fi

if [ "$COMMAND" = "distributable_python" ] ; then
    distributable_python $2
    exit $?
fi
