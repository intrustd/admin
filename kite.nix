{ pkgs, kite-lib, pure-build, ... }:
let python = pkgs.python3;

    admin-app = python.pkgs.buildPythonPackage rec {
      pname = "kite-admin";
      version = "0.1.0";

      src = if pure-build then ./. else ./dist/kite-admin-0.1.0.tar.gz;

      doCheck = false;

      propagatedBuildInputs = with python.pkgs; [ flask pyopenssl itsdangerous jinja2 click werkzeug markupsafe pyudev celery redis ];

      meta = {
        homepage = "https://flywithkite.com";
        description = "Kite Photos App";
      };
    };
in
{
  kite.meta = {
    slug = "admin";
    name = "Kite Admin";
    authors = [ "Travis Athougies<travis@athougies.net>" ];
    app-url = "https://admin.flywithkite.com/";
    icon = "https://admin.flywithkite.com/images/admin.svg";
  };

  kite.identifier = "admin.flywithkite.com";

  kite.services.admin =
    kite-lib.templates.uwsgi {
      name = "admin";

      pythonPackages = [ admin-app ];
      module = "kite.admin:app";
      socket = "/kite/admin.sock";
      http = "0.0.0.0:80";

      environment = { KITE_APPLIANCE_DIR = "/kite/appliance"; };
    };

  kite.services.redis =
    kite-lib.templates.redis {
      name = "redis";

      savePoints = [];
      databases = 2;
    };

  kite.services.celery =
   let celery = python.withPackages (ps: [ admin-app ]);
   in { name = "celery";
        environment = { KITE_APPLIANCE_DIR = "/kite/appliance"; };
        startExec = ''
          ${celery}/bin/celery -A kite.admin.app.celery -A kite.admin.app.celery worker --loglevel=INFO --concurrency=2
        '';
        autostart = true; };

  kite.runAsAdmin = true;
  kite.singleton = true;

  kite.bindMounts = [ "/run/udev" ];
}
