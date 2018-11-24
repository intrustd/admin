{pkgs ? import <nixpkgs> {
    inherit system;
}, system ? builtins.currentSystem}:

let
  nodePackages = import ./default.nix {
    inherit pkgs system;
  };
in
nodePackages // {
  "stork-js-../../../stork-js" = nodePackages."stork-js-../../../stork-js".override {
    src = pkgs.kite.src + /stork-js;
  };
}
