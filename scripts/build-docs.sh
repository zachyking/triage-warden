#!/bin/bash
set -e

MDBOOK_VERSION="v0.4.40"

echo "Downloading mdBook ${MDBOOK_VERSION}..."
curl -sSL "https://github.com/rust-lang/mdBook/releases/download/${MDBOOK_VERSION}/mdbook-${MDBOOK_VERSION}-x86_64-unknown-linux-gnu.tar.gz" | tar -xz

echo "Building documentation..."
./mdbook build docs-site

echo "Build complete! Output in docs-site/book/"
