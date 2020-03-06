#!/bin/bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

NUM_ARGS_REQUIRED=2
if [ $# -lt "${NUM_ARGS_REQUIRED}" ]; then
    cat <<EOF
Usage: $0 <cert_dir> [<regions> ... ]

    Generate certs for AWS endpoints, add enough wildcards for the regions
    provided.  At least one region must be provided.

    Stores generated certs in <cert_dir>.

EOF
    exit 1
fi

run () {
    echo "+" "$@" 1>&2
    "$@"
}

color () {
    COLOR=$1
    MESSAGE=$2
    case "${COLOR}" in
    red)
        echo -e "\e[31m${MESSAGE}\e[39m"
        ;;
    blue)
        echo -e "\e[94m${MESSAGE}\e[39m"
        ;;
    green)
        echo -e "\e[32m${MESSAGE}\e[39m"
        ;;
    *)
        echo "Unrecognized color: ${COLOR}" 1>&2
        echo -e "${MESSAGE}"
        ;;
    esac
}

CERT_DIR=$1
shift
REGIONS=( "$@" )

if [ -e "$CERT_DIR" ]; then
    color green "Directory $CERT_DIR already exists!"
    read -p "Do you want to delete it? " -n 1 -r
    echo    # (optional) move to a new line
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        exit 1
    fi
    run rm -rf "$CERT_DIR"
fi
run mkdir "$CERT_DIR"

color blue "Generating certificates for endpoints in \"${REGIONS[*]}\""
WILDCARDS=()
for region in "${REGIONS[@]}"; do
    WILDCARDS+=("*.$region.amazonaws.com")
done
run go run github.com/FiloSottile/mkcert -install \
    -cert-file "$CERT_DIR/cert.pem" \
    -key-file "$CERT_DIR/private.pem" \
    "*.amazonaws.com" "${WILDCARDS[@]}"

color blue "Converting private key to RSA private key"
run openssl rsa -in "$CERT_DIR/private.pem" -out "$CERT_DIR/private.key"

color green "Certificates generated!  Set the following environment variables:"
color green "export MONIE_CERT_FILE=$CERT_DIR/cert.pem"
color green "export MONIE_KEY_FILE=$CERT_DIR/private.key"
