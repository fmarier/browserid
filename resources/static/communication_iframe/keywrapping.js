/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*globals BrowserID: true, console: true */

BrowserID.KeyWrapping = (function() {
  "use strict";

  var jwcrypto,
      keyserverChan,
      bid = BrowserID,
      user = bid.User,
      storage = bid.Storage;

  // this is for calls that are non-interactive
  function _open_hidden_keyserver_iframe() {
    var keyServer = 'http://127.0.0.1:9000'; // TODO: move this to the config file
    if (!keyserverChan) {
      var doc = window.document;
      var iframe = doc.createElement("iframe");
      iframe.style.display = "none";
      doc.body.appendChild(iframe);
      iframe.src = keyServer + "/communication_iframe";
      keyserverChan = Channel.build({
        window: iframe.contentWindow,
        origin: keyServer,
        scope: "mozks_ni"
      });
    }
  }

  function generateAndWrap(identity, origin, successCB, failureCB) {
    _open_hidden_keyserver_iframe();

    if (identity !== storage.getLoggedIn(origin)) {
      failureCB('Invalid identity');
    } else {
      keyserverChan.call({
        method: 'get_user_key',
        params: {
          identity: identity
        },
        success: function (userKey) {
          if (!jwcrypto) {
            jwcrypto = require('./lib/jwcrypto.js');
          }

          jwcrypto.addEntropy('TODO: random', 256); // TODO: use entropy provided by BID server
          var plainKey = jwcrypto.generateKey(128);
          var bundle = JSON.stringify({audience: origin, secretkey: plainKey});

          var wrappedKey = jwcrypto.encrypt(bundle, userKey);

          successCB(plainKey, wrappedKey);
        },
        error: function (err) {
          failureCB(err);
        }
      });
    }
  }

  function unwrap(identity, origin, wrappedKey, successCB, failureCB) {
    _open_hidden_keyserver_iframe();

    if (identity !== storage.getLoggedIn(origin)) {
      failureCB('Invalid identity');
    } else {
      keyserverChan.call({
        method: 'get_user_key',
        params: {
          identity: identity
        },
        success: function (userKey) {
          if (!jwcrypto) {
            jwcrypto = require('./lib/jwcrypto.js');
          }

          var d = jwcrypto.decrypt(wrappedKey, userKey);
          var bundle = JSON.parse(d);

          if (bundle.audience === origin) {
            successCB(bundle.secretkey);
          } else {
            failureCB('Origin mismatch');
          }
        },
        error: function (err) {
          failureCB(err);
        }
      });
    }
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
