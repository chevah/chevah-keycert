# Files holding passwords.
# Non-empty passwors MUST be at least 5 characters long.
# (Limitation imposed by ssh-keygen for password-protected PCKS8 keys.)
# Non-empty passwords MUST start with a letter.
# (Limitation imposed by the script testing self-generated keys.)
# Complex passwords must be at least 10 characters long.
# (Limitation imposed by the script testing self-generated keys.)

> pass_file_empty
echo 'chevah' > pass_file_simple
echo 'V^#~(?)%&\/+-1.,="*`!>|<:$;@N' > pass_file_complex
PASS_TYPES="empty simple complex"

> comm_file_empty
echo 'chevah' > comm_file_simple
echo '    V^#~(?)%&\/+-1.    ,="*`!>|<:$;@N' > comm_file_complex
echo 'âåæāăąǎǟȁȃȧȺαἀащѝѱҡҩժݐሀᠠァぁ妈媽✯➾♤♟⚅🂠⚇𓀀😀☠️👩🏿‍🦽🦺⛈🪐🥂🏁🏴‍☠️🐈‍⬛' > comm_file_unicode
COMM_TYPES="empty simple complex unicode"
