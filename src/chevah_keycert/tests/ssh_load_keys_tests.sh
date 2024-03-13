#!/usr/bin/env bash
#
# Test loading keys generated with various SSH key generators.

set -euo pipefail

# Key types to generate with puttygen, ssh-keygen, ssh-keygen-g3.
# Accepted parameters (one or more): ed25519, ecdsa, rsa, dsa.
# Generating large size RSA and DSA keys takes a lot of CPU time.
KEY_TYPES=$*
if [ -z "$KEY_TYPES" ]; then
    # If no parameters given, test all.
    KEY_TYPES="ed25519 ecdsa dsa rsa"
fi

KEYCERT_CMD="../build-py3/bin/python ../keycert-demo.py"
KEYCERT_NO_ERRORS_FILE="load_keys_tests_errors_none"
KEYCERT_EXPECTED_ERRORS_FILE="load_keys_tests_errors_expected"
KEYCERT_UNEXPECTED_ERRORS_FILE="load_keys_tests_errors_unexpected"
KEYCERT_DEMOSCRIPT_ERRORS_FILE="load_keys_tests_errors_demoscript"

# puttygen supports key type "rsa1", but it's not used here.
# private-sshcom doesn't work with ed25519 and ecdsa in puttygen 0.74.
PUTTY_PRIV_OUTPUTS="private private-openssh private-openssh-new private-sshcom"
PUTTY_PUB_OUTPUTS="public public-openssh"

# The "default" option is more of a placeholder for not using an extra format.
OPENSSH_FORMATS="default RFC4716 PKCS8 PEM"

TECTIA_FORMATS="secsh2 pkcs1 pkcs8 pkcs12 openssh2 openssh2-aes"
TECTIA_HASHES="sha1 sha224 sha256 sha384 sha512"

# Empty the files holding test results, if present.
> $KEYCERT_NO_ERRORS_FILE
> $KEYCERT_EXPECTED_ERRORS_FILE
> $KEYCERT_UNEXPECTED_ERRORS_FILE
> $KEYCERT_DEMOSCRIPT_ERRORS_FILE

# Common routines like setting password files.
source ../src/chevah_keycert/tests/ssh_common_test_inc.sh
# FIXME:50
# Unicode comments are not supported.
COMM_TYPES="empty simple complex"
# FIXME:52
# Comments starting with a blank are not supported.
COMM_TYPES="empty simple"

# First parameter is the private or public key file.
# Second (optional) parameter is the password.
keycert_load_key(){
    local keycert_opts="ssh-load-key --file $1"
    if [ "$#" = 2 ]; then
        local keycert_opts="$keycert_opts --password $2"
    fi
    set +e
    $KEYCERT_CMD $keycert_opts
    local keycert_err_code=$?
    set -e
    if [ $keycert_err_code -eq 0 ]; then
        echo $1 >> $KEYCERT_NO_ERRORS_FILE
    elif [ $keycert_err_code -eq 1 ]; then
        echo $1 >> $KEYCERT_EXPECTED_ERRORS_FILE
    elif [ $keycert_err_code -eq 2 ]; then
        echo $1 >> $KEYCERT_UNEXPECTED_ERRORS_FILE
    elif [ $keycert_err_code -eq 3 ]; then
        echo $1 >> $KEYCERT_DEMOSCRIPT_ERRORS_FILE
    else
        (>&2 echo "Unexpected error code: $keycert_err_code")
        exit 42
    fi
}

putty_keys_test(){
    local bit_lengths="$1"
    local pass_type
    local pass_file
    local priv_key_file
    local pub_key_file
    local pub_output

    for bits in $bit_lengths; do
        for pass_type in $PASS_TYPES; do
            for comm_type in $COMM_TYPES; do
                echo -n "Generating $KEY key of type $PUTTY_PRIV_OUTPUT and size $bits"
                echo " with $pass_type password and $comm_type comment:"
                priv_key_file="putty_${KEY}_${bits}_${PUTTY_PRIV_OUTPUT}_${pass_type}pass_${comm_type}comm"
                pass_file="pass_file_${pass_type}"
                comm_file="comm_file_${comm_type}"
                puttygen --random-device /dev/random -C "$(cat $comm_file)" --new-passphrase $pass_file \
                    -t $KEY -O $PUTTY_PRIV_OUTPUT -b $bits -o $priv_key_file
                keycert_load_key $priv_key_file $(cat $pass_file)
                # Extract/test public key in all supported public formats, but only when:
                #    1) The private key is in Putty's own format.
                #    2) The complex password is used.
                if [ "$PUTTY_PRIV_OUTPUT" = "private" -a $pass_type = "complex" ]; then
                    for pub_output in $PUTTY_PUB_OUTPUTS; do
                        pub_key_file="putty_${KEY}_${bits}_${pub_output}_${pass_type}pass_${comm_type}comm"
                        puttygen --old-passphrase $pass_file -O $pub_output -o $pub_key_file $priv_key_file
                        keycert_load_key $pub_key_file
                        rm $pub_key_file
                    done
                fi
                rm $priv_key_file
            done
        done
    done
}

openssh_format_set(){
    if [ $format != "default" ]; then
        OPENSSH_OPTS="$OPENSSH_OPTS -m $format"
    fi
}

openssh_keys_test(){
    local bit_lengths="$1"
    local pass_type
    local pass_file
    local format
    local priv_key_file
    local pub_key_file

    for bits in $bit_lengths; do
        for pass_type in $PASS_TYPES; do
            pass_file="pass_file_${pass_type}"
            for comm_type in $COMM_TYPES; do
                comm_file="comm_file_${comm_type}"
                for format in $OPENSSH_FORMATS; do
                    priv_key_file=openssh_${KEY}_${bits}_${format}_${pass_type}pass_${comm_type}comm
                    pub_key_file=$priv_key_file.pub
                    if [ $pass_type = "empty" ]; then
                        if [ $format = "PKCS8" ]; then
                            if [ $KEY = "ecdsa" -o $KEY = "rsa" -o $KEY = "dsa" ]; then
                                # Minimum 5 characters required for these combinations.
                                (>&2 echo "Not generating $format $KEY key with $pass_type password.")
                                continue
                            fi
                        fi
                        OPENSSH_OPTS=""
                        openssh_format_set
                        ssh-keygen -C "$(cat $comm_file)" -t $KEY -b $bits $OPENSSH_OPTS -f $priv_key_file -N ""
                    else
                        OPENSSH_OPTS="-N $(cat $pass_file)"
                        openssh_format_set
                        ssh-keygen -C "$(cat $comm_file)" -t $KEY -b $bits $OPENSSH_OPTS -f $priv_key_file
                    fi
                    keycert_load_key $priv_key_file $(cat $pass_file)
                    keycert_load_key $pub_key_file
                    rm $priv_key_file $pub_key_file
                done
            done
        done
    done
}

tectia_keys_test(){
    local bit_lengths="$1"
    local pass_type
    local pass_file
    local format
    local fips_mode
    local priv_key_file
    local pub_key_file
    local gen_opts

    for bits in $bit_lengths; do
        # FIXME:53
        # Tectia tests are currently disabled.
        break
        for pass_type in $PASS_TYPES; do
            pass_file="pass_file_${pass_type}"
            for comm_type in $COMM_TYPES; do
                comm_file="comm_file_${comm_type}"
                for format in $TECTIA_FORMATS; do
                    for fips_mode in nofips fips; do
                        if [ $fips_mode = "fips" -a $KEY = "ed25519" ]; then
                            continue
                        elif [ $fips_mode = "fips" -a $pass_type = "empty" ]; then
                            continue
                        elif [ $fips_mode = "fips" -a "${format%openssh2*}" = "" ]; then
                            # "OpenSSH2 keys operations are forbidden when in FIPS mode."
                            continue
                        fi
                        for hash in $TECTIA_HASHES; do
                            gen_opts="-b $bits -t $KEY --key-format $format --key-hash $hash"
                            if [ $fips_mode = "fips" ]; then
                                gen_opts="$gen_opts --fips-mode"
                            fi
                            priv_key_file=tectia_${KEY}_${bits}_${format}_${hash}_${fips_mode}_${pass_type}_${comm_type}
                            pub_key_file=$priv_key_file.pub
                            if [ $pass_type = "empty" ]; then
                                ssh-keygen-g3 -c "$(cat $comm_file)" $gen_opts -P $(pwd)/$priv_key_file
                            else
                                ssh-keygen-g3 -c "$(cat $comm_file)" $gen_opts -p $(cat $pass_file) $(pwd)/$priv_key_file
                            fi
                            keycert_load_key $priv_key_file $(cat $pass_file)
                            keycert_load_key $pub_key_file
                            rm $priv_key_file $pub_key_file
                        done
                    done
                done
            done
        done
    done
}



# Putty's puttygen tests.
for KEY in $KEY_TYPES; do
    for PUTTY_PRIV_OUTPUT in $PUTTY_PRIV_OUTPUTS; do
        if [ $KEY = "ed25519" -a $PUTTY_PRIV_OUTPUT = "private-openssh-new" ]; then
            # No need to force new OpenSSH format for ED25519 keys.
            continue
        fi
        if [ $PUTTY_PRIV_OUTPUT = "private-sshcom" ]; then
            if [ $KEY = "ed25519" -o $KEY = "ecdsa" ]; then
                # Not working in puttygen 0.74.
                continue
            fi
        fi
        # Test specific numbers of bits per key type.
        case $KEY in
            "ed25519")
                putty_keys_test "256"
                ;;
            "ecdsa")
                putty_keys_test "256 384 521"
                ;;
            "rsa")
                putty_keys_test "512 2048 4096"
                ;;
            "dsa")
                # An unusual prime size is also tested.
                putty_keys_test "2111 3072 4096"
                ;;
        esac
    done
done

# OpenSSH's ssh-keygen tests.
for KEY in $KEY_TYPES; do
    case $KEY in
        "ed25519")
            openssh_keys_test "256"
            ;;
        "ecdsa")
            openssh_keys_test "256 384 521"
            ;;
        "rsa")
            # An unusual prime size is also tested.
            openssh_keys_test "1024 2111 3072 8192"
            ;;
        "dsa")
            openssh_keys_test "1024"
            ;;
    esac
done

# Tectia's ssh-keygen-g3 tests.
for KEY in $KEY_TYPES; do
    case $KEY in
        "ed25519")
            tectia_keys_test "256"
            ;;
        "ecdsa")
            tectia_keys_test "256 384 521"
            ;;
        "rsa")
            tectia_keys_test "512 1024 2048 3072 4096 8192"
            ;;
        "dsa")
            tectia_keys_test "1024 2048 3072 4096"
            ;;
    esac
done

# Cleanup test files.
rm pass_file_* comm_file_*

echo -ne "\nCombinations tested: "
cat $KEYCERT_NO_ERRORS_FILE $KEYCERT_EXPECTED_ERRORS_FILE $KEYCERT_UNEXPECTED_ERRORS_FILE | wc -l

echo -ne "\nCombinations with no errors: "
cat $KEYCERT_NO_ERRORS_FILE | wc -l
cat $KEYCERT_NO_ERRORS_FILE
rm $KEYCERT_NO_ERRORS_FILE

echo -ne "\nCombinations with demo script errors: "
cat $KEYCERT_DEMOSCRIPT_ERRORS_FILE | wc -l
cat $KEYCERT_DEMOSCRIPT_ERRORS_FILE
rm $KEYCERT_DEMOSCRIPT_ERRORS_FILE

echo -ne "\nCombinations with expected errors: "
cat $KEYCERT_EXPECTED_ERRORS_FILE | wc -l
cat $KEYCERT_EXPECTED_ERRORS_FILE
rm $KEYCERT_EXPECTED_ERRORS_FILE

echo -ne "\nCombinations with unexpected errors: "
cat $KEYCERT_UNEXPECTED_ERRORS_FILE | wc -l
cat $KEYCERT_UNEXPECTED_ERRORS_FILE

if [ -s $KEYCERT_UNEXPECTED_ERRORS_FILE ]; then
    rm $KEYCERT_UNEXPECTED_ERRORS_FILE
    exit 13
else
    rm $KEYCERT_UNEXPECTED_ERRORS_FILE
fi
