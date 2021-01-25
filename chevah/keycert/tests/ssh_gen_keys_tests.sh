#!/usr/bin/env bash
#
# Generate supported key types and test them with various SSH key tools.

set -euo pipefail

# Key types to generate and then test with puttygen, ssh-keygen, ssh-keygen-g3.
# Accepted parameters (one or more): ed25519, ecdsa, rsa, dsa.
# Generating large size RSA and DSA keys takes a lot of CPU time.
KEY_TYPES=$*
if [ -z "$KEY_TYPES" ]; then
    # If no parameters given, test all key types.
    KEY_TYPES="ed25519 ecdsa rsa dsa"
fi

KEYCERT_CMD="../build-keycert/bin/python ../keycert-demo.py"
KEYCERT_FORMATS="openssh openssh_v1 putty"

SUCCESS_FILE="gen_keys_tests_success"
ERROR_FILE="gen_keys_tests_error"

# Empty the files holding test results, if present.
> $SUCCESS_FILE
> $ERROR_FILE

# Files holding passwords. Non-empty passwords MUST start with a letter.
> pass_file_empty
echo 'chevah' > pass_file_simple
# Complex passwords must be at least 10 characters long.
echo 'V^#ev1uj#kq$N' > pass_file_complex
# No difference in testing simple and complex passwords, so we skip the former. XXX
PASS_TYPES="empty simple complex"


sort_tests_per_error(){
    local cmd_to_test=$*
    local cmd_err_code

    set +e
    $cmd_to_test
    cmd_err_code=$?
    set -e

    # Record last parameter.
    if [ $cmd_err_code -eq 0 ]; then
        echo "${@: -1}" >> $SUCCESS_FILE
    else
        echo "${@: -1}" >> $ERROR_FILE
    fi
}

puttygen_tests(){
    local priv_key=$1
    local pub_key=${1}.pub
    
    sort_tests_per_error puttygen -O fingerprint $pub_key
    sort_tests_per_error puttygen -o /dev/null --old-passphrase pass_file_${2} -L $priv_key
}

sshkeygen_tests(){
    local priv_key=$1
    local pub_key=${1}.pub
    
    sort_tests_per_error ssh-keygen -l -f $pub_key
    if [ $2 = "empty" ]; then
        sort_tests_per_error ssh-keygen -y -f $priv_key
    else
        sort_tests_per_error ssh-keygen -y -P "$(cat pass_file_${2})" -f $priv_key
    fi
}

# First parameter is the key type.
# Second (optional) parameter is the password. MUST start with a letter
keycert_gen_keys(){
    local key_size
    local key_format
    local key_type=$1
    local key_pass_type
    local keycert_opts="ssh-gen-key --key-type $key_type"

    # Remove first parameter, the password should be now first, if existing.
    shift
    # Check if there is a password to be used.
    if [[ "${1:0:1}" =~ [a-zA-Z] ]]; then
        # First remaining parameter is the password, as it starts with a non-digit.
        keycert_opts="$keycert_opts --key-password $1 --key-comment $1"
        # Check password type by password length.
        if [ ${#1} -ge 10 ]; then
            key_pass_type="complex"
        else
            key_pass_type="simple"
        fi
        shift
    else
        key_pass_type="empty"
    fi

    for key_size in $*; do
        for key_format in $KEYCERT_FORMATS; do
            if [ $key_format = "openssh" -a $key_type = "ed25519" ]; then
                # "Cannot serialize Ed25519 key to openssh format".
                (>&2 echo "Not generating $key_type key with the $key_format format.")
                continue
            fi
            final_keycert_opts="$keycert_opts --key-size $key_size --key-format $key_format"
            # An associated public key is also generated with same name + '.pub'.
            key_file=${key_type}_${key_size}_${key_format}_${key_pass_type}
            $KEYCERT_CMD $final_keycert_opts --key-file $key_file
            # OpenSSH's tool will complain of unsafe permissions.
            chmod 600 $key_file
            case $key_format in
                openssh*)
                    sshkeygen_tests $key_file $key_pass_type
                    ;;
                putty)
                    puttygen_tests $key_file $key_pass_type
                    ;;
            esac
            rm $key_file ${key_file}.pub
        done
    done
}



for pass_type in $PASS_TYPES; do
    pass=$(cat pass_file_${pass_type})

    for key in $KEY_TYPES; do
        case $key in
            "ed25519")
                keycert_gen_keys ed25519 $pass 256
                ;;
            "ecdsa")
                keycert_gen_keys ecdsa $pass 256 384 521
                ;;
            "rsa")
                # An unusual prime size is also tested.
                keycert_gen_keys rsa $pass 1024 2111 3072 4096 8192
                ;;
            "dsa")
                keycert_gen_keys dsa $pass 1024 2048 3072 4096
                ;;
        esac
    done

    rm pass_file_${pass_type}
done

echo -ne "\nCombinations tested: "
cat $SUCCESS_FILE $ERROR_FILE | wc -l

echo -ne "\nCombinations with no errors: "
cat $SUCCESS_FILE | wc -l
cat $SUCCESS_FILE
rm $SUCCESS_FILE

echo -ne "\nCombinations with errors: "
cat $ERROR_FILE | wc -l
cat $ERROR_FILE

if [ -s $ERROR_FILE ]; then
    rm $ERROR_FILE
    exit 13
else
    rm $ERROR_FILE
fi
