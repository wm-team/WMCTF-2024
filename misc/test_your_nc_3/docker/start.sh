#!/bin/bash

# if [[ -z "$FLAG" ]]; then
#     FLAG="flag{no_flag}"
# fi

# chmod 700 /flag || true
# echo "$FLAG" > /flag
chown root:root /flag
chmod 000 /flag

export FLAG=not_flag
unset FLAG

export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
exec socat TCP-LISTEN:9999,reuseaddr,fork 'EXEC:/bin/114sh,stderr'