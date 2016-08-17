#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <input-dir>"
	exit 1
fi

IDIR="$1"

if [ ! -d "$IDIR" ]; then
	echo "$0: '$IDIR' is not a directory."
	exit 1
fi

find "$IDIR" -maxdepth 1 -type f -name "*.tar.gz" -exec md5sum {} \; > MD5SUMS

exit 0

