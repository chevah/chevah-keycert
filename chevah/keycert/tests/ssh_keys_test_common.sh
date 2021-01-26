# Files holding passwords. Non-empty passwords MUST start with a letter.
> pass_file_empty
echo 'None' > pass_file_simple
# Complex passwords must be at least 10 characters long.
echo 'V^#~(?)%&\/+-1.,="*`!>|<:$;@N' > pass_file_complex
PASS_TYPES="empty simple complex"
