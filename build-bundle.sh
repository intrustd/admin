#!/bin/sh

echo "Building nix manifest"
nix-build ../../nix/build-bundle.nix --argstr kite-app-module "`pwd`/kite.nix" -o result.json

SHA256SUM=$(cat ./result.json | sha256sum | awk '{print $1}')
echo "Output $SHA256SUM.sign"
../../nix/sign ../../key.pem ./result.json ./result.json.sign
