import <intrustd/nix/hydra-app-jobsets.nix> {
  description = "Intrustd Admin App";
  src = { type = "git"; value = "git://github.com/intrustd/admin.git"; emailresponsible = true; };
}
