#!/usr/bin/env bash
#
# Test loading keys generated with various SSH key generators.

set -euo pipefail

keycert_cmd="./build-keycert/bin/python keycert-demo.py"

# Types to get with supported generators: ssh-keygen, ssh-keygen-g3, puttygen.
key_types="ed25519 ecdsa" # Add "rsa dsa" for more coverage.

# The "default" option is more of a placeholder for not using an extra format.
openssh_formats="default RFC4716 PKCS8 PEM"

# puttygen supports key type "rsa1", but it's not used here.
# private-sshcom doesn't work with ed25519 and ecdsa in puttygen 0.74.
putty_priv_outputs="private private-openssh private-openssh-new private-sshcom"
putty_pub_outputs="public public-openssh"

# Empty file holding test errors.
> ssh_keys_tests_errors

# Files holding passwords.
> pass_file_empty
echo 'chevah' > pass_file_simple
echo 'V^#ev1uj#kq$N' > pass_file_complex
pass_types="empty simple complex"



# First parameter is the private or public key file.
# Second (optional) parameter is the password.
keycert_load_key(){
    local keycert_opts="ssh-load-key --file $1"
    if [ "$#" = 2 ]; then
        local keycert_opts="$keycert_opts --password $2"
    fi
    set +e
    $keycert_cmd $keycert_opts
    if [ $? -ne 0 ]; then
        echo $1 >> ssh_keys_tests_errors 
    fi
    set -e
}

openssh_format_set(){
    if [ $format != "default" ]; then
        ssh_extra_opts="$ssh_extra_opts -m $format"
    fi
}

openssh_keys_gen(){
    local bit_lengths_to_test="$1"

    for bits in $bit_lengths_to_test; do
        for pass_type in $pass_types; do
            pass_file="pass_file_${pass_type}"
            for format in $openssh_formats; do
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
                    ssh_extra_opts=""
                    openssh_format_set
                    ssh-keygen -C "$(cat $pass_file)" -t $key -b $bits $ssh_extra_opts -f $priv_key_file -N ""
                else
                    ssh_extra_opts="-N $(cat $pass_file)"
                    openssh_format_set
                    ssh-keygen -C "$(cat $pass_file)" -t $key -b $bits $ssh_extra_opts -f $priv_key_file
                fi
                keycert_load_key $priv_key_file $(cat $pass_file)
                keycert_load_key $pub_key_file
            done
        done
    done
}

putty_keys_gen(){
    local bit_lengths_to_test="$1"

    for bits in $bit_lengths_to_test; do
        for pass_type in $pass_types; do
            echo "Generating $key key of type $priv_output and size $bits with $pass_type password:"
            priv_key_file="putty_${key}_${bits}_${priv_output}"
            pass_file="pass_file_${pass_type}"
            puttygen -C "$(cat $pass_file)" --new-passphrase $pass_file -t $key -O $priv_output -b $bits -o $priv_key_file
            keycert_load_key $priv_key_file $(cat $pass_file)
            # Extract and test public key in all supported formats.
            for pub_output in $putty_pub_outputs; do
                echo "Generating $key key of type $pub_output and size $bits with $pass_type password:"
                pub_key_file="putty_${key}_${bits}_${pub_output}"
                puttygen --old-passphrase $pass_file -O $pub_output -o $pub_key_file $priv_key_file
                keycert_load_key $pub_key_file
            done
        done
    done
}



# OpenSSH's ssh-keygen tests.
for key in $key_types; do
    case $key in
        "ed25519")
            openssh_keys_gen "256"
            ;;
        "ecdsa")
            openssh_keys_gen "256 384 521"
            ;;
        "rsa")
            # An unusual prime size is also tested.
            openssh_keys_gen "1024 2048 2111 3072 4096 8192"
            ;;
        "dsa")
            openssh_keys_gen "1024"
            ;;
    esac
done

# Putty's puttygen tests.
for key in $key_types; do
    for priv_output in $putty_priv_outputs; do
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
                putty_keys_gen "256"
                ;;
            "ecdsa")
                putty_keys_gen "256 384 521"
                ;;
            "rsa")
                # An unusual prime size is also tested.
                putty_keys_gen "1024 2048 2111 3072 4096 8192"
                ;;
            "dsa")
                putty_keys_gen "1024 2048 3072 4096"
                ;;
        esac
    done
done

echo -ne "\nCombinations tested: "
ls -1 openssh_* putty_* | wc -l
ls -1 openssh_* putty_*

# Cleanup test files.
rm pass_file_* openssh_* putty_*

if [ -s ssh_keys_tests_errors ]; then
    echo -ne "\nCombinations with errors: "
    cat ssh_keys_tests_errors | wc -l
    cat ssh_keys_tests_errors
    exit 13
else
    echo -e "\nThere were no errors."
fi
