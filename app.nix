{ pkgs, intrustd, pure-build, ... }:
let python = pkgs.python3;

   redis-py = python.pkgs.callPackage ./pkgs/redis-py {};
   our-kombu = python.pkgs.callPackage ./pkgs/kombu { Pyro4 = our-pyro4; };
   our-pyro4 = python.pkgs.callPackage ./pkgs/pyro4 {};
   our-celery = python.pkgs.celery.override { kombu = our-kombu; };

    admin-app = python.pkgs.buildPythonPackage {
      pname = "intrustd-admin";
      version = "0.1.0";

      src =  if pure-build then ./. else ./dist/intrustd-admin-0.1.0.tar.gz;

      doCheck = false;

      propagatedBuildInputs = with python.pkgs;
        [ flask pyopenssl itsdangerous jinja2 click werkzeug
          markupsafe pyudev our-celery redis-py pillow sqlalchemy ];

      meta = {
        homepage = "https://intrustd.com";
        description = "Intrustd Admin App";
      };
    };

  celery-bin = python.withPackages (ps: [ admin-app ]);
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

      environment = { INTRUSTD_APPLIANCE_DIR = "/intrustd/appliance"; INTRUSTD_UPDATE_LOG_DIR = "/intrustd/appliance/logs/updates"; };
      extraOptions = "--limit-post 10485760"; # Limit post size to 10 MB
    };

  app.services.redis =
    intrustd.templates.redis {
      name = "redis";

      savePoints = [];
      databases = 2;
    };

  app.services.celery-worker =
   { name = "celery-worker";
     environment = { INTRUSTD_APPLIANCE_DIR = "/intrustd/appliance"; };
     startExec = ''
       ${celery-bin}/bin/celery -A intrustd.admin.app.celery worker --loglevel=INFO --concurrency=8
     '';
     autostart = true;
   };

  app.services.celery-beat =
   { name = "celery-beat";
     environment = { INTRUSTD_APPLIANCE_DIR = "/intrustd/appliance"; };
     startExec = ''
        ${pkgs.coreutils}/bin/rm -f /intrustd/celerybeat.pid
        ${celery-bin}/bin/celery -A intrustd.admin.app.celery beat -s /intrustd/celerybeat-schedule
     '';
     autostart = true;
   };

  app.runAsAdmin = true;
  app.singleton = true;

  app.bindMounts = [ "/run/udev" ];
}
