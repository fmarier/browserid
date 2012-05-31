/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*globals BrowserID: true, console: true */

BrowserID.KeyWrapping = (function() {
  "use strict";

  var jwcrypto;

  function generateAndWrap(identity, successCB, failureCB) {
    setTimeout(function () {
      if (!jwcrypto) {
        jwcrypto = require('./lib/jwcrypto.js');
      }

      if (identity) { // TODO: check identity matches logged in identity
        var origin = 'http://127.0.0.1:8000'; // TODO: read from BrowserID.User
        // TODO: check that user is logged into that origin/RP

        var userKey = JSON.stringify("TODO: secret"); // TODO: read from browserid.org's localStorage

        jwcrypto.addEntropy('TODO: random', 256); // TODO: use entropy provided by BID server
        var plainKey = jwcrypto.generateKey(128);
        var bundle = JSON.stringify({audience: origin, secretkey: plainKey});

        var wrappedKey = jwcrypto.encrypt(bundle, userKey);

        successCB(plainKey, wrappedKey);
      } else {
        failureCB('Invalid identity');
      }
    }, 0);
  }

  function unwrap(identity, wrappedKey, successCB, failureCB) {
    setTimeout(function () {
      if (!jwcrypto) {
        jwcrypto = require('./lib/jwcrypto.js');
      }

      if (identity) { // TODO: check identity matches logged in identity
        var origin = 'http://127.0.0.1:8000'; // TODO: read from BrowserID.User
        // TODO: check that user is logged into that origin/RP

        var userKey = JSON.stringify("TODO: secret"); // TODO: read from browserid.org's localStorage
        var d = jwcrypto.decrypt(wrappedKey, userKey);
        var bundle = JSON.parse(d);

        if (bundle.audience === origin) {
          successCB(bundle.secretkey);
        } else {
          failureCB('Origin mismatch');
        }
      } else {
        failureCB('Invalid identity');
      }
    }, 0);
  }

  return {
    /**
     * Generate a new random key and return it along with a copy of
     * that same key wrapped using the user's secret key.
     * @method generateAndWrap
     */
    generateAndWrap: generateAndWrap,

    /**
     * Unwrap the given key using the user's secret key
     * @method unwrap
     */
    unwrap: unwrap
  };
}());
