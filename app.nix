{ pkgs, intrustd, pure-build, ... }:
let python = pkgs.python3;

    admin-app = python.pkgs.buildPythonPackage rec {
      pname = "intrustd-admin";
      version = "0.1.0";

      src = if pure-build then ./. else ./dist/intrustd-admin-0.1.0.tar.gz;

      doCheck = false;

      propagatedBuildInputs = with python.pkgs; [ flask pyopenssl itsdangerous jinja2 click werkzeug markupsafe pyudev celery redis ];

      meta = {
        homepage = "https://intrustd.com";
        description = "Intrustd Admin App";
      };
    };
in
{
  app.meta = {
    slug = "admin";
    name = "Intrustd Admin";
    authors = [ "Travis Athougies<travis@athougies.net>" ];
    app-url = "https://admin.intrustd.com/";
    icon = "https://admin.intrustd.com/images/admin.svg";
  };

  app.identifier = "admin.intrustd.com";

  app.services.admin =
    intrustd.templates.uwsgi {
      name = "admin";

      pythonPackages = [ admin-app ];
      module = "intrustd.admin:app";
      socket = "/intrustd/admin.sock";
      http = "0.0.0.0:80";

      environment = { INTRUSTD_APPLIANCE_DIR = "/intrustd/appliance"; };
    };

  app.services.redis =
    intrustd.templates.redis {
      name = "redis";

      savePoints = [];
      databases = 2;
    };

  app.services.celery =
   let celery = python.withPackages (ps: [ admin-app ]);
   in { name = "celery";
        environment = { INTRUSTD_APPLIANCE_DIR = "/intrustd/appliance"; };
        startExec = ''
          ${celery}/bin/celery -A intrustd.admin.app.celery -A intrustd.admin.app.celery worker --loglevel=INFO --concurrency=2
        '';
        autostart = true; };

  app.runAsAdmin = true;
  app.singleton = true;

  app.bindMounts = [ "/run/udev" ];
}
