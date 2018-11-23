{ kite-admin-app ? { outPath = ./.; name = "kite-admin-app"; }
, pkgs ? import <nixpkgs> {}
}:
let
  nodePackages = import "${pkgs.path}/pkgs/top-level/node-packages.nix" {
    inherit pkgs;
    inherit (pkgs) stdenv nodejs fetchurl fetchgit;
    neededNatives = [ pkgs.python ] ++ pkgs.lib.optional pkgs.stdenv.isLinux pkgs.utillinux;
    self = nodePackages;
    generated = ./js/local-admin.nix;
  };
in rec {
  tarball = pkgs.runCommand "kite-admin-app-1.0.0.tgz" { buildInputs = [ pkgs.nodejs ]; } ''
    mv `HOME=$PWD npm pack ${kite-admin-app}` $out
  '';
  build = nodePackages.buildNodePackage {
    name = "kite-admin-app-1.0.0";
    src = [ tarball ];
    buildInputs = nodePackages.nativeDeps."kite-admin-app" or [];
    deps = [ nodePackages.by-spec."font-awesome"."^4.7.0" nodePackages.by-spec."immutable"."^3.8.2" nodePackages.by-spec."react"."^16.5.2" nodePackages.by-spec."react-dom"."^16.5.2" nodePackages.by-spec."react-router"."^4.3.1" nodePackages.by-spec."react-router-dom"."^4.3.1" nodePackages.by-spec."react-transition-group"."^2.5.0" nodePackages.by-spec."stork-js"."file:../../../stork-js" nodePackages.by-spec."uikit"."^3.0.0-rc.11" ];
    peerDependencies = [];
  };
}