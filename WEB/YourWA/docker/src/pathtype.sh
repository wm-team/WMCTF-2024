if [ -f "$1" ]; then
    printf 'file' | tr -d '\n'
elif [ -d "$1" ]; then
    printf 'dir' | tr -d '\n'
fi