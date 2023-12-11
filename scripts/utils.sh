function errexit(){
    echo "error in >> $STAGE"
    exit 1
}


function echo_header() {
    set +x
    echo -e "\n********************************************"
    echo "*** $1"
    echo -e "********************************************\n"
    set -x
}


function create_symlink() {
    if [ $# -ne 2 ]; then
        echo "create_symlink: wrong number of arguments (requires 2)"
        errexit
    fi

    from_path=$1
    to_path=$2

    # unlink existing symlink, if any
    if [[ -f "$from_path" ]]; then
        unlink "$from_path"
    fi

    # create the symlink
    ln -s "$to_path" "$from_path"
}
