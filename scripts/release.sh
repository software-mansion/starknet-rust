#!/bin/bash
set -euxo pipefail

VERSION=$1

# Update CHANGELOG.md
sed -i.bak "s/## \[Unreleased\]/## \[Unreleased\]\n\n## \[${VERSION}\] - $(TZ=Europe/Krakow date '+%Y-%m-%d')/" CHANGELOG.md
rm CHANGELOG.md.bak 2> /dev/null

# Update workspace version in Cargo.toml
sed -i.bak "/\[workspace.package\]/,/version =/ s/version = \".*/version = \"${VERSION}\"/" Cargo.toml
rm Cargo.toml.bak 2> /dev/null

# Update dependencies versions in Cargo.toml
sed -i.bak -e '/^\[workspace\.dependencies\]$/,/^\[/{' \
           -e '/^[[:space:]]*starknet-rust[^[:space:]]*[[:space:]]*=/ s/version = "[^"]*"/version = "'"${VERSION}"'"/g' \
           -e '}' Cargo.toml
rm -f Cargo.toml.bak 2>/dev/null
