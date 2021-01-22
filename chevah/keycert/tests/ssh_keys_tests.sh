#!/usr/bin/env bash
#
# Test loading keys generated with various SSH key generators.

set -euo pipefail

KEYCERT_CMD="../build-keycert/bin/python ../keycert-demo.py"
KEYCERT_NO_ERRORS_FILE="ssh_keys_tests_errors_none"
KEYCERT_EXPECTED_ERRORS_FILE="ssh_keys_tests_errors_expected"
KEYCERT_UNEXPECTED_ERRORS_FILE="ssh_keys_tests_errors_unexpected"

# Key types to generate with: puttygen, ssh-keygen, ssh-keygen-g3.
# Testing RSA and DSA with large key sizes takes a lot of CPU time.
KEY_TYPES="ed25519 ecdsa rsa dsa"

# puttygen supports key type "rsa1", but it's not used here.
# private-sshcom doesn't work with ed25519 and ecdsa in puttygen 0.74.
PUTTY_PRIV_OUTPUTs="private private-openssh private-openssh-new private-sshcom"
PUTTY_PUB_OUTPUTs="public public-openssh"

# The "default" option is more of a placeholder for not using an extra format.
OPENSSH_FORMATS="default RFC4716 PKCS8 PEM"

TECTIA_FORMATS="secsh2 pkcs1 pkcs8 pkcs12 openssh2 openssh2-aes"
TECTIA_HASHES="sha1 sha224 sha256 sha384 sha512"

# Empty the files holding test results, if present.
> $KEYCERT_NO_ERRORS_FILE
> $KEYCERT_EXPECTED_ERRORS_FILE
> $KEYCERT_UNEXPECTED_ERRORS_FILE

# Files holding passwords.
> pass_file_empty
echo 'chevah' > pass_file_simple
echo 'V^#ev1uj#kq$N' > pass_file_complex
# No difference in testing simple and complex passwords, so we skip the former.
PASS_TYPES="empty complex"



# First parameter is the private or public key file.
# Second (optional) parameter is the password.
keycert_load_key(){
    local keycert_opts="ssh-load-key --file $1"
    if [ "$#" = 2 ]; then
        local keycert_opts="$keycert_opts --password $2"
    fi
    set +e
    $KEYCERT_CMD $keycert_opts
    if [ $? -eq 0 ]; then
        echo $1 >> $KEYCERT_NO_ERRORS_FILE
    elif [ $? -eq 1 ]; then
        echo $1 >> $KEYCERT_EXPECTED_ERRORS_FILE
    else
        echo $1 >> $KEYCERT_UNEXPECTED_ERRORS_FILE
    fi
    set -e
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
            echo "Generating $key key of type $priv_output and size $bits with $pass_type password:"
            priv_key_file="putty_${key}_${bits}_${priv_output}"
            pass_file="pass_file_${pass_type}"
            puttygen --random-device /dev/random -C "$(cat $pass_file)" --new-passphrase $pass_file \
                -t $key -O $priv_output -b $bits -o $priv_key_file
            keycert_load_key $priv_key_file $(cat $pass_file)
            # Extract and test public key in all supported formats.
            for pub_output in $PUTTY_PUB_OUTPUTs; do
                pub_key_file="putty_${key}_${bits}_${pub_output}"
                puttygen --old-passphrase $pass_file -O $pub_output -o $pub_key_file $priv_key_file
                keycert_load_key $pub_key_file
                rm $pub_key_file
            done
            rm $priv_key_file
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
            for format in $OPENSSH_FORMATS; do
                priv_key_file=openssh_${key}_${bits}_${format}_${pass_type}
                pub_key_file=$priv_key_file.pub
                if [ $pass_type = "empty" ]; then
                    if [ $format = "PKCS8" ]; then
                        if [ $key = "ecdsa" -o $key = "rsa" -o $key = "dsa" ]; then
                            # Minimum 5 characters required for these combinations.
                            (>&2 echo "Not generating $format $key key with $pass_type password.")
                            break
                        fi
                    fi
                    OPENSSH_OPTS=""
                    openssh_format_set
                    ssh-keygen -C "$(cat $pass_file)" -t $key -b $bits $OPENSSH_OPTS -f $priv_key_file -N ""
                else
                    OPENSSH_OPTS="-N $(cat $pass_file)"
                    openssh_format_set
                    ssh-keygen -C "$(cat $pass_file)" -t $key -b $bits $OPENSSH_OPTS -f $priv_key_file
                fi
                keycert_load_key $priv_key_file $(cat $pass_file)
                keycert_load_key $pub_key_file
                rm $priv_key_file $pub_key_file
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
        for pass_type in $PASS_TYPES; do
            pass_file="pass_file_${pass_type}"
            for format in $TECTIA_FORMATS; do
                for fips_mode in nofips fips; do
                    if [ $fips_mode = "fips" -a $key = "ed25519" ]; then
                        break
                    elif [ $fips_mode = "fips" -a $pass_type = "empty" ]; then
                        break
                    elif [ $fips_mode = "fips" -a "${format%openssh2*}" = "" ]; then
                        # "OpenSSH2 keys operations are forbidden when in FIPS mode."
                        break
                    fi
                    for hash in $TECTIA_HASHES; do
                        gen_opts="-b $bits -t $key --key-format $format --key-hash $hash"
                        if [ $fips_mode = "fips" ]; then
                            gen_opts="$gen_opts --fips-mode"
                        fi
                        priv_key_file=tectia_${key}_${bits}_${format}_${hash}_${fips_mode}_${pass_type}
                        pub_key_file=$priv_key_file.pub
                        if [ $pass_type = "empty" ]; then
                            ssh-keygen-g3 -c "$(cat $pass_file)" $gen_opts -P $(pwd)/$priv_key_file
                        else
                            ssh-keygen-g3 -c "$(cat $pass_file)" $gen_opts -p $(cat $pass_file) $(pwd)/$priv_key_file
                        fi
                        keycert_load_key $priv_key_file $(cat $pass_file)
                        keycert_load_key $pub_key_file
                        rm $priv_key_file $pub_key_file
                    done
                done
            done
        done
    done
}



# Putty's puttygen tests.
for key in $KEY_TYPES; do
    for priv_output in $PUTTY_PRIV_OUTPUTs; do
        if [ $key = "ed25519" -a $priv_output = "private-openssh-new" ]; then
            # No need to force new OpenSSH format for ED25519 keys.
            break
        fi
        if [ $priv_output = "private-sshcom" ]; then
            if [ $key = "ed25519" -o $key = "ecdsa" ]; then
                # Not working in puttygen 0.74.
                break
            fi
        fi
        # Test specific numbers of bits per key type.
        case $key in
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
                putty_keys_test "1024 2048 2111 3072 4096"
                ;;
        esac
    done
done

# OpenSSH's ssh-keygen tests.
for key in $KEY_TYPES; do
    case $key in
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

# # Tectia's ssh-keygen-g3 tests.
# for key in $KEY_TYPES; do
#     case $key in
#         "ed25519")
#             tectia_keys_test "256"
#             ;;
#         "ecdsa")
#             tectia_keys_test "256 384 521"
#             ;;
#         "rsa")
#             tectia_keys_test "512 1024 2048 3072 4096 8192"
#             ;;
#         "dsa")
#             tectia_keys_test "1024 2048 3072 4096"
#             ;;
#     esac
# done

# Cleanup test files.
rm pass_file_*

echo -ne "\nCombinations tested: "
cat $KEYCERT_NO_ERRORS_FILE $KEYCERT_EXPECTED_ERRORS_FILE $KEYCERT_UNEXPECTED_ERRORS_FILE | wc -l

echo -ne "\nCombinations with no errors: "
cat $KEYCERT_NO_ERRORS_FILE | wc -l
cat $KEYCERT_NO_ERRORS_FILE
rm $KEYCERT_NO_ERRORS_FILE

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
