#!/bin/bash

function cleanup ()
{
	unlink "$SYMLINK"
}

trap cleanup EXIT

if [ $# -lt 1 ]; then
	echo "Usage: $0 <input-dir>"
	exit 1
fi

IDIR="$1"

if [ ! -d "$IDIR" ]; then
	echo "$0: '$IDIR' is not a directory."
	exit 1
fi

ROCKTEMP="$(ls -1 "$IDIR/"*.rocktemp 2>/dev/null)"

if [ ! -f "$ROCKTEMP" ]; then
	echo "$0: template file *.rocktemp not found in '$IDIR'."
	exit 1
fi

# Create a symbolic link to input directory.
SYMLINK="$(basename "$ROCKTEMP" ".rocktemp")"

ln -s "$IDIR" "$SYMLINK"

if [ $? -ne 0 ]; then
	echo "$0: tarball creation failed (cannot create a symlink)."
	exit 1
fi

TARBALL="$(basename "$ROCKTEMP" ".rocktemp").tar.gz"

tar chzf "$TARBALL" "$SYMLINK/"

if [ $? -ne 0 ]; then
	echo "$0: tarball creation failed."
	exit 1
fi

MD5SUM="$(md5sum "$TARBALL")"

if [ $? -ne 0 ]; then
	echo "$0: cannot calculate md5sum of the tarball"
	exit 1
fi

MD5SUM="$(echo $MD5SUM | cut -d ' ' -f 1)"

sed -e 's/@MD5_SUM@/'$MD5SUM'/g' "$ROCKTEMP" > "$(basename "$ROCKTEMP" ".rocktemp").rockspec"

exit 0

