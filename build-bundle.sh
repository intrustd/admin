#!/bin/sh

echo "Building nix manifest"

nix-build ../../intrustd/nix/build-bundle.nix --argstr app-module "`pwd`/app.nix" -o result.json --arg systems 'let pkgs = import <nixpkgs> {}; in builtins.listToAttrs [ { name = pkgs.hostPlatform.config; value = pkgs; } { name = "x86_64-unknown-linux-musl"; value=pkgs;}]'  --option secret-key-files "$NIX_SIGNING_KEY"

SHA256SUM=$(cat ./result.json | sha256sum | awk '{print $1}')
echo "Output $SHA256SUM.sign"
../../intrustd/nix/sign ../../key.pem ./result.json ./result.json.sign

if [ -n "$INTRUSTD_APPLIANCE_DIR" ]; then
  cp result.json "$INTRUSTD_APPLIANCE_DIR"/manifests/$SHA256SUM
  cp result.json.sign "$INTRUSTD_APPLIANCE_DIR"/manifests/$SHA256SUM.sign
fi
