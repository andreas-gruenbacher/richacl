#!/bin/sh -e

echo "Running autoreconf..."
autoreconf -f -i

echo
echo "Proceed by configuring with:"
echo "    ./configure"
echo
