import <intrustd/nix/hydra-app-jobsets.nix> {
  description = "Intrustd Admin App";
  src = { type = "git"; value = "git://github.com/kitecomputing/photos.git"; emailresponsible = true; };
}
