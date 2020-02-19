# This file has been generated by node2nix 1.6.0. Do not edit!

{nodeEnv, fetchurl, fetchgit, globalBuildInputs ? []}:

let
  sources = {
    "@babel/runtime-7.8.4" = {
      name = "_at_babel_slash_runtime";
      packageName = "@babel/runtime";
      version = "7.8.4";
      src = fetchurl {
        url = "https://registry.npmjs.org/@babel/runtime/-/runtime-7.8.4.tgz";
        sha512 = "neAp3zt80trRVBI1x0azq6c57aNBqYZH8KhMm3TaB7wEI5Q4A2SHfBHE8w9gOhI/lrqxtEbXZgQIrHP+wvSGwQ==";
      };
    };
    "attr-accept-2.0.0" = {
      name = "attr-accept";
      packageName = "attr-accept";
      version = "2.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/attr-accept/-/attr-accept-2.0.0.tgz";
        sha512 = "I9SDP4Wvh2ItYYoafEg8hFpsBe96pfQ+eabceShXt3sw2fbIP96+Aoj9zZE0vkZNAkXXzHJATVRuWz+h9FxJxQ==";
      };
    };
    "base64-js-1.3.1" = {
      name = "base64-js";
      packageName = "base64-js";
      version = "1.3.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/base64-js/-/base64-js-1.3.1.tgz";
        sha512 = "mLQ4i2QO1ytvGWFWmcngKO//JXAQueZvwEKtjgQFM4jIK0kU+ytMfplL8j+n5mspOfjHwoAg+9yhb7BwAHm36g==";
      };
    };
    "bootstrap-4.4.1" = {
      name = "bootstrap";
      packageName = "bootstrap";
      version = "4.4.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/bootstrap/-/bootstrap-4.4.1.tgz";
        sha512 = "tbx5cHubwE6e2ZG7nqM3g/FZ5PQEDMWmMGNrCUBVRPHXTJaH7CBDdsLeu3eCh3B1tzAxTnAbtmrzvWEvT2NNEA==";
      };
    };
    "buffer-5.4.3" = {
      name = "buffer";
      packageName = "buffer";
      version = "5.4.3";
      src = fetchurl {
        url = "https://registry.npmjs.org/buffer/-/buffer-5.4.3.tgz";
        sha512 = "zvj65TkFeIt3i6aj5bIvJDzjjQQGs4o/sNoezg1F1kYap9Nu2jcUdpwzRSJTHMMzG0H7bZkn4rNQpImhuxWX2A==";
      };
    };
    "cache-polyfill-1.0.1" = {
      name = "cache-polyfill";
      packageName = "cache-polyfill";
      version = "1.0.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/cache-polyfill/-/cache-polyfill-1.0.1.tgz";
        sha512 = "bIMkvMYuXvOOUMoxUChREYXT6OZi4kvPcRQrmEyaPkLR21sLwDfhdhxxSifZmoiPGQHNEdbeuVNtO5oXbSP31Q==";
      };
    };
    "decode-uri-component-0.2.0" = {
      name = "decode-uri-component";
      packageName = "decode-uri-component";
      version = "0.2.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/decode-uri-component/-/decode-uri-component-0.2.0.tgz";
        sha1 = "eb3913333458775cb84cd1a1fae062106bb87545";
      };
    };
    "dexie-2.0.4" = {
      name = "dexie";
      packageName = "dexie";
      version = "2.0.4";
      src = fetchurl {
        url = "https://registry.npmjs.org/dexie/-/dexie-2.0.4.tgz";
        sha512 = "aQ/s1U2wHxwBKRrt2Z/mwFNHMQWhESerFsMYzE+5P5OsIe5o1kgpFMWkzKTtkvkyyEni6mWr/T4HUJuY9xIHLA==";
      };
    };
    "dom-helpers-3.4.0" = {
      name = "dom-helpers";
      packageName = "dom-helpers";
      version = "3.4.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/dom-helpers/-/dom-helpers-3.4.0.tgz";
        sha512 = "LnuPJ+dwqKDIyotW1VzmOZ5TONUN7CwkCR5hrgawTUbkBGYdeoNLZo6nNfGkCrjtE1nXXaj7iMMpDa8/d9WoIA==";
      };
    };
    "event-target-shim-3.0.2" = {
      name = "event-target-shim";
      packageName = "event-target-shim";
      version = "3.0.2";
      src = fetchurl {
        url = "https://registry.npmjs.org/event-target-shim/-/event-target-shim-3.0.2.tgz";
        sha512 = "HK5GhnEAkm7fLy249GtF7DIuYmjLm85Ft6ssj7DhVl8Tx/z9+v0W6aiIVUdT4AXWGYy5Fc+s6gqBI49Bf0LejQ==";
      };
    };
    "file-selector-0.1.12" = {
      name = "file-selector";
      packageName = "file-selector";
      version = "0.1.12";
      src = fetchurl {
        url = "https://registry.npmjs.org/file-selector/-/file-selector-0.1.12.tgz";
        sha512 = "Kx7RTzxyQipHuiqyZGf+Nz4vY9R1XGxuQl/hLoJwq+J4avk/9wxxgZyHKtbyIPJmbD4A66DWGYfyykWNpcYutQ==";
      };
    };
    "font-awesome-4.7.0" = {
      name = "font-awesome";
      packageName = "font-awesome";
      version = "4.7.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/font-awesome/-/font-awesome-4.7.0.tgz";
        sha1 = "8fa8cf0411a1a31afd07b06d2902bb9fc815a133";
      };
    };
    "history-4.10.1" = {
      name = "history";
      packageName = "history";
      version = "4.10.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/history/-/history-4.10.1.tgz";
        sha512 = "36nwAD620w12kuzPAsyINPWJqlNbij+hpK1k9XRloDtym8mxzGYl2c17LnV6IAGB2Dmg4tEa7G7DlawS0+qjew==";
      };
    };
    "hoist-non-react-statics-2.5.5" = {
      name = "hoist-non-react-statics";
      packageName = "hoist-non-react-statics";
      version = "2.5.5";
      src = fetchurl {
        url = "https://registry.npmjs.org/hoist-non-react-statics/-/hoist-non-react-statics-2.5.5.tgz";
        sha512 = "rqcy4pJo55FTTLWt+bU8ukscqHeE/e9KWvsOW2b/a3afxQZhwkQdT1rPPCJ0rYXdj4vNcasY8zHTH+jF/qStxw==";
      };
    };
    "http-parser-js-0.4.13" = {
      name = "http-parser-js";
      packageName = "http-parser-js";
      version = "0.4.13";
      src = fetchurl {
        url = "https://registry.npmjs.org/http-parser-js/-/http-parser-js-0.4.13.tgz";
        sha1 = "3bd6d6fde6e3172c9334c3b33b6c193d80fe1137";
      };
    };
    "ieee754-1.1.13" = {
      name = "ieee754";
      packageName = "ieee754";
      version = "1.1.13";
      src = fetchurl {
        url = "https://registry.npmjs.org/ieee754/-/ieee754-1.1.13.tgz";
        sha512 = "4vf7I2LYV/HaWerSo3XmlMkp5eZ83i+/CDluXi/IGTs/O1sejBNhTtnxzmRZfvOUqj7lZjqHkeTvpgSFDlWZTg==";
      };
    };
    "immutable-3.8.2" = {
      name = "immutable";
      packageName = "immutable";
      version = "3.8.2";
      src = fetchurl {
        url = "https://registry.npmjs.org/immutable/-/immutable-3.8.2.tgz";
        sha1 = "c2439951455bb39913daf281376f1530e104adf3";
      };
    };
    "intrustd-git://github.com/intrustd/js" = {
      name = "intrustd";
      packageName = "intrustd";
      version = "1.0.0";
      src = fetchgit {
        url = "git://github.com/intrustd/js";
        rev = "b26aa4c22d58cd235db60cc165447e9aa24a5206";
        sha256 = "2a969d986b12b300020fe7fd8dba4abc60e8c44a0625071b6e18dd7921b04881";
      };
    };
    "invariant-2.2.4" = {
      name = "invariant";
      packageName = "invariant";
      version = "2.2.4";
      src = fetchurl {
        url = "https://registry.npmjs.org/invariant/-/invariant-2.2.4.tgz";
        sha512 = "phJfQVBuaJM5raOpJjSfkiD6BpbCE4Ns//LaXl6wGYtUBY83nWS6Rf9tXm2e8VaK60JEjYldbPif/A2B1C2gNA==";
      };
    };
    "isarray-0.0.1" = {
      name = "isarray";
      packageName = "isarray";
      version = "0.0.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/isarray/-/isarray-0.0.1.tgz";
        sha1 = "8a18acfca9a8f4177e09abfc6038939b05d1eedf";
      };
    };
    "jquery-3.4.1" = {
      name = "jquery";
      packageName = "jquery";
      version = "3.4.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/jquery/-/jquery-3.4.1.tgz";
        sha512 = "36+AdBzCL+y6qjw5Tx7HgzeGCzC81MDDgaUP8ld2zhx58HdqXGoBd+tHdrBMiyjGQs0Hxs/MLZTu/eHNJJuWPw==";
      };
    };
    "js-tokens-4.0.0" = {
      name = "js-tokens";
      packageName = "js-tokens";
      version = "4.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz";
        sha512 = "RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ==";
      };
    };
    "loose-envify-1.4.0" = {
      name = "loose-envify";
      packageName = "loose-envify";
      version = "1.4.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz";
        sha512 = "lyuxPGr/Wfhrlem2CL/UcnUc1zcqKAImBDzukY7Y5F/yQiNdko6+fRLevlw1HgMySw7f611UIY408EtxRSoK3Q==";
      };
    };
    "mithril-1.1.7" = {
      name = "mithril";
      packageName = "mithril";
      version = "1.1.7";
      src = fetchurl {
        url = "https://registry.npmjs.org/mithril/-/mithril-1.1.7.tgz";
        sha512 = "1SAkGeVrIVvkUHlPHvR3pXdWzNfTzmS/fBAe+rC2ApEBfZFFc+idi8Qg/M5JoW/sZkIDXSfQYVgvENMIhBIVAg==";
      };
    };
    "nprogress-0.2.0" = {
      name = "nprogress";
      packageName = "nprogress";
      version = "0.2.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/nprogress/-/nprogress-0.2.0.tgz";
        sha1 = "cb8f34c53213d895723fcbab907e9422adbcafb1";
      };
    };
    "object-assign-4.1.1" = {
      name = "object-assign";
      packageName = "object-assign";
      version = "4.1.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz";
        sha1 = "2109adc7965887cfc05cbbd442cac8bfbb360863";
      };
    };
    "path-to-regexp-1.8.0" = {
      name = "path-to-regexp";
      packageName = "path-to-regexp";
      version = "1.8.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-1.8.0.tgz";
        sha512 = "n43JRhlUKUAlibEJhPeir1ncUID16QnEjNpwzNdO3Lm4ywrBpBZ5oLD0I6br9evr1Y9JTqwRtAh7JLoOzAQdVA==";
      };
    };
    "popper.js-1.16.1" = {
      name = "popper.js";
      packageName = "popper.js";
      version = "1.16.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/popper.js/-/popper.js-1.16.1.tgz";
        sha512 = "Wb4p1J4zyFTbM+u6WuO4XstYx4Ky9Cewe4DWrel7B0w6VVICvPwdOpotjzcf6eD8TsckVnIMNONQyPIUFOUbCQ==";
      };
    };
    "prop-types-15.7.2" = {
      name = "prop-types";
      packageName = "prop-types";
      version = "15.7.2";
      src = fetchurl {
        url = "https://registry.npmjs.org/prop-types/-/prop-types-15.7.2.tgz";
        sha512 = "8QQikdH7//R2vurIJSutZ1smHYTcLpRWEOlHnzcWHmBYrOGUysKwSsrC89BCiFj3CbrfJ/nXFdJepOVrY1GCHQ==";
      };
    };
    "query-string-6.11.0" = {
      name = "query-string";
      packageName = "query-string";
      version = "6.11.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/query-string/-/query-string-6.11.0.tgz";
        sha512 = "jS+me8X3OEGFTsF6kF+vUUMFG/d3WUCvD7bHhfZP5784nOq1pjj8yau/u86nfOncmcN6ZkSWKWkKAvv/MGxzLA==";
      };
    };
    "querystringify-2.1.1" = {
      name = "querystringify";
      packageName = "querystringify";
      version = "2.1.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/querystringify/-/querystringify-2.1.1.tgz";
        sha512 = "w7fLxIRCRT7U8Qu53jQnJyPkYZIaR4n5151KMfcJlO/A9397Wxb1amJvROTK6TOnp7PfoAmg/qXiNHI+08jRfA==";
      };
    };
    "react-16.12.0" = {
      name = "react";
      packageName = "react";
      version = "16.12.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/react/-/react-16.12.0.tgz";
        sha512 = "fglqy3k5E+81pA8s+7K0/T3DBCF0ZDOher1elBFzF7O6arXJgzyu/FW+COxFvAWXJoJN9KIZbT2LXlukwphYTA==";
      };
    };
    "react-avatar-editor-11.0.7" = {
      name = "react-avatar-editor";
      packageName = "react-avatar-editor";
      version = "11.0.7";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-avatar-editor/-/react-avatar-editor-11.0.7.tgz";
        sha512 = "GbNYBd1/L1QyuU9VRvOW0hSkW1R0XSneOWZFgqI5phQf6dX+dF/G3/AjiJ0hv3JWh2irMQ7DL0oYDKzwtTnNBQ==";
      };
    };
    "react-dom-16.12.0" = {
      name = "react-dom";
      packageName = "react-dom";
      version = "16.12.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-dom/-/react-dom-16.12.0.tgz";
        sha512 = "LMxFfAGrcS3kETtQaCkTKjMiifahaMySFDn71fZUNpPHZQEzmk/GiAeIT8JSOrHB23fnuCOMruL2a8NYlw+8Gw==";
      };
    };
    "react-dropzone-10.2.1" = {
      name = "react-dropzone";
      packageName = "react-dropzone";
      version = "10.2.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-dropzone/-/react-dropzone-10.2.1.tgz";
        sha512 = "Me5nOu8hK9/Xyg5easpdfJ6SajwUquqYR/2YTdMotsCUgJ1pHIIwNsv0n+qcIno0tWR2V2rVQtj2r/hXYs2TnQ==";
      };
    };
    "react-is-16.12.0" = {
      name = "react-is";
      packageName = "react-is";
      version = "16.12.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-is/-/react-is-16.12.0.tgz";
        sha512 = "rPCkf/mWBtKc97aLL9/txD8DZdemK0vkA3JMLShjlJB3Pj3s+lpf1KaBzMfQrAmhMQB0n1cU/SUGgKKBCe837Q==";
      };
    };
    "react-lifecycles-compat-3.0.4" = {
      name = "react-lifecycles-compat";
      packageName = "react-lifecycles-compat";
      version = "3.0.4";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-lifecycles-compat/-/react-lifecycles-compat-3.0.4.tgz";
        sha512 = "fBASbA6LnOU9dOU2eW7aQ8xmYBSXUIWr+UmF9b1efZBazGNO+rcXT/icdKnYm2pTwcRylVUYwW7H1PHfLekVzA==";
      };
    };
    "react-router-4.3.1" = {
      name = "react-router";
      packageName = "react-router";
      version = "4.3.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-router/-/react-router-4.3.1.tgz";
        sha512 = "yrvL8AogDh2X42Dt9iknk4wF4V8bWREPirFfS9gLU1huk6qK41sg7Z/1S81jjTrGHxa3B8R3J6xIkDAA6CVarg==";
      };
    };
    "react-router-dom-4.3.1" = {
      name = "react-router-dom";
      packageName = "react-router-dom";
      version = "4.3.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-router-dom/-/react-router-dom-4.3.1.tgz";
        sha512 = "c/MlywfxDdCp7EnB7YfPMOfMD3tOtIjrQlj/CKfNMBxdmpJP8xcz5P/UAFn3JbnQCNUxsHyVVqllF9LhgVyFCA==";
      };
    };
    "react-transition-group-2.9.0" = {
      name = "react-transition-group";
      packageName = "react-transition-group";
      version = "2.9.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/react-transition-group/-/react-transition-group-2.9.0.tgz";
        sha512 = "+HzNTCHpeQyl4MJ/bdE0u6XRMe9+XG/+aL4mCxVN4DnPBQ0/5bfHWPDuOZUzYdMj94daZaZdCCc1Dzt9R/xSSg==";
      };
    };
    "regenerator-runtime-0.13.3" = {
      name = "regenerator-runtime";
      packageName = "regenerator-runtime";
      version = "0.13.3";
      src = fetchurl {
        url = "https://registry.npmjs.org/regenerator-runtime/-/regenerator-runtime-0.13.3.tgz";
        sha512 = "naKIZz2GQ8JWh///G7L3X6LaQUAMp2lvb1rvwwsURe/VXwD6VMfr+/1NuNw3ag8v2kY1aQ/go5SNn79O9JU7yw==";
      };
    };
    "requires-port-1.0.0" = {
      name = "requires-port";
      packageName = "requires-port";
      version = "1.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/requires-port/-/requires-port-1.0.0.tgz";
        sha1 = "925d2601d39ac485e091cf0da5c6e694dc3dcaff";
      };
    };
    "resolve-pathname-3.0.0" = {
      name = "resolve-pathname";
      packageName = "resolve-pathname";
      version = "3.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/resolve-pathname/-/resolve-pathname-3.0.0.tgz";
        sha512 = "C7rARubxI8bXFNB/hqcp/4iUeIXJhJZvFPFPiSPRnhU5UPxzMFIl+2E6yY6c4k9giDJAhtV+enfA+G89N6Csng==";
      };
    };
    "scheduler-0.18.0" = {
      name = "scheduler";
      packageName = "scheduler";
      version = "0.18.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/scheduler/-/scheduler-0.18.0.tgz";
        sha512 = "agTSHR1Nbfi6ulI0kYNK0203joW2Y5W4po4l+v03tOoiJKpTBbxpNhWDvqc/4IcOw+KLmSiQLTasZ4cab2/UWQ==";
      };
    };
    "split-on-first-1.1.0" = {
      name = "split-on-first";
      packageName = "split-on-first";
      version = "1.1.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/split-on-first/-/split-on-first-1.1.0.tgz";
        sha512 = "43ZssAJaMusuKWL8sKUBQXHWOpq8d6CfN/u1p4gUzfJkM05C8rxTmYrkIPTXapZpORA6LkkzcUulJ8FqA7Uudw==";
      };
    };
    "strict-uri-encode-2.0.0" = {
      name = "strict-uri-encode";
      packageName = "strict-uri-encode";
      version = "2.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/strict-uri-encode/-/strict-uri-encode-2.0.0.tgz";
        sha1 = "b9c7330c7042862f6b142dc274bbcc5866ce3546";
      };
    };
    "tiny-invariant-1.1.0" = {
      name = "tiny-invariant";
      packageName = "tiny-invariant";
      version = "1.1.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/tiny-invariant/-/tiny-invariant-1.1.0.tgz";
        sha512 = "ytxQvrb1cPc9WBEI/HSeYYoGD0kWnGEOR8RY6KomWLBVhqz0RgTwVO9dLrGz7dC+nN9llyI7OKAgRq8Vq4ZBSw==";
      };
    };
    "tiny-warning-1.0.3" = {
      name = "tiny-warning";
      packageName = "tiny-warning";
      version = "1.0.3";
      src = fetchurl {
        url = "https://registry.npmjs.org/tiny-warning/-/tiny-warning-1.0.3.tgz";
        sha512 = "lBN9zLN/oAf68o3zNXYrdCt1kP8WsiGW8Oo2ka41b2IM5JL/S1CTyX1rW0mb/zSuJun0ZUrDxx4sqvYS2FWzPA==";
      };
    };
    "tslib-1.10.0" = {
      name = "tslib";
      packageName = "tslib";
      version = "1.10.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/tslib/-/tslib-1.10.0.tgz";
        sha512 = "qOebF53frne81cf0S9B41ByenJ3/IuH8yJKngAX35CmiZySA0khhkovshKK+jGCaMnVomla7gVlIcc3EvKPbTQ==";
      };
    };
    "url-parse-1.4.7" = {
      name = "url-parse";
      packageName = "url-parse";
      version = "1.4.7";
      src = fetchurl {
        url = "https://registry.npmjs.org/url-parse/-/url-parse-1.4.7.tgz";
        sha512 = "d3uaVyzDB9tQoSXFvuSUNFibTd9zxd2bkVrDRvF5TmvWWQwqE4lgYJ5m+x1DbecWkw+LK4RNl2CU1hHuOKPVlg==";
      };
    };
    "utf8-3.0.0" = {
      name = "utf8";
      packageName = "utf8";
      version = "3.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/utf8/-/utf8-3.0.0.tgz";
        sha512 = "E8VjFIQ/TyQgp+TZfS6l8yp/xWppSAHzidGiRrqe4bK4XP9pTRyKFgGJpO3SN7zdX4DeomTrwaseCHovfpFcqQ==";
      };
    };
    "value-equal-1.0.1" = {
      name = "value-equal";
      packageName = "value-equal";
      version = "1.0.1";
      src = fetchurl {
        url = "https://registry.npmjs.org/value-equal/-/value-equal-1.0.1.tgz";
        sha512 = "NOJ6JZCAWr0zlxZt+xqCHNTEKOsrks2HQd4MqhP1qy4z1SkbEP467eNx6TgDKXMvUOb+OENfJCZwM+16n7fRfw==";
      };
    };
    "vcard-parser-1.0.0" = {
      name = "vcard-parser";
      packageName = "vcard-parser";
      version = "1.0.0";
      src = fetchurl {
        url = "https://registry.npmjs.org/vcard-parser/-/vcard-parser-1.0.0.tgz";
        sha512 = "rSEjrjBK3of4VimMR5vBjLLcN5ZCSp9yuVzyx5i4Fwx74Yd0s+DnHtSit/wAAtj1a7/T/qQc0ykwXADoD0+fTQ==";
      };
    };
    "warning-4.0.3" = {
      name = "warning";
      packageName = "warning";
      version = "4.0.3";
      src = fetchurl {
        url = "https://registry.npmjs.org/warning/-/warning-4.0.3.tgz";
        sha512 = "rpJyN222KWIvHJ/F53XSZv0Zl/accqHR8et1kpaMTD/fLCRxtV8iX8czMzY7sVZupTI3zcUTg8eycS2kNF9l6w==";
      };
    };
    "web-streams-polyfill-1.3.2" = {
      name = "web-streams-polyfill";
      packageName = "web-streams-polyfill";
      version = "1.3.2";
      src = fetchurl {
        url = "https://registry.npmjs.org/web-streams-polyfill/-/web-streams-polyfill-1.3.2.tgz";
        sha1 = "3719245e909282d93967825f44bcd550e9c03995";
      };
    };
  };
  args = {
    name = "intrustd-admin-app";
    packageName = "intrustd-admin-app";
    version = "1.0.0";
    src = ./.;
    dependencies = [
      sources."@babel/runtime-7.8.4"
      sources."attr-accept-2.0.0"
      sources."base64-js-1.3.1"
      sources."bootstrap-4.4.1"
      sources."buffer-5.4.3"
      sources."cache-polyfill-1.0.1"
      sources."decode-uri-component-0.2.0"
      sources."dexie-2.0.4"
      sources."dom-helpers-3.4.0"
      sources."event-target-shim-3.0.2"
      sources."file-selector-0.1.12"
      sources."font-awesome-4.7.0"
      sources."history-4.10.1"
      sources."hoist-non-react-statics-2.5.5"
      sources."http-parser-js-0.4.13"
      sources."ieee754-1.1.13"
      sources."immutable-3.8.2"
      sources."intrustd-git://github.com/intrustd/js"
      sources."invariant-2.2.4"
      sources."isarray-0.0.1"
      sources."jquery-3.4.1"
      sources."js-tokens-4.0.0"
      sources."loose-envify-1.4.0"
      sources."mithril-1.1.7"
      sources."nprogress-0.2.0"
      sources."object-assign-4.1.1"
      sources."path-to-regexp-1.8.0"
      sources."popper.js-1.16.1"
      sources."prop-types-15.7.2"
      sources."query-string-6.11.0"
      sources."querystringify-2.1.1"
      sources."react-16.12.0"
      sources."react-avatar-editor-11.0.7"
      sources."react-dom-16.12.0"
      sources."react-dropzone-10.2.1"
      sources."react-is-16.12.0"
      sources."react-lifecycles-compat-3.0.4"
      sources."react-router-4.3.1"
      sources."react-router-dom-4.3.1"
      sources."react-transition-group-2.9.0"
      sources."regenerator-runtime-0.13.3"
      sources."requires-port-1.0.0"
      sources."resolve-pathname-3.0.0"
      sources."scheduler-0.18.0"
      sources."split-on-first-1.1.0"
      sources."strict-uri-encode-2.0.0"
      sources."tiny-invariant-1.1.0"
      sources."tiny-warning-1.0.3"
      sources."tslib-1.10.0"
      sources."url-parse-1.4.7"
      sources."utf8-3.0.0"
      sources."value-equal-1.0.1"
      sources."vcard-parser-1.0.0"
      sources."warning-4.0.3"
      sources."web-streams-polyfill-1.3.2"
    ];
    buildInputs = globalBuildInputs;
    meta = {
      description = "Intrustd admin app";
      license = "MIT";
    };
    production = true;
    bypassCache = true;
  };
in
{
  tarball = nodeEnv.buildNodeSourceDist args;
  package = nodeEnv.buildNodePackage args;
  shell = nodeEnv.buildNodeShell args;
}