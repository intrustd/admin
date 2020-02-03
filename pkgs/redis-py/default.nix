{ buildPythonPackage, fetchPypi, ... }:

buildPythonPackage rec {
  pname = "redis";
  version = "3.2.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "8ca418d2ddca1b1a850afa1680a7d2fd1f3322739271de4b704e0d4668449273";
  };

  # tests require a running redis
  doCheck = false;

  meta = {
    description = "Python client for Redis key-value store";
    homepage = "https://pypi.python.org/pypi/redis/";
  };
}
