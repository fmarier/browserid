/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*globals BrowserID: true, console: true */

BrowserID.KeyWrapping = (function() {
  "use strict";

  var KEYSERVER = 'http://127.0.0.1:9000'; // TODO: move this to the config file

  var jwcrypto,
      keyserverChan,
      bid = BrowserID,
      user = bid.User,
      storage = bid.Storage;

  // this is for calls that are non-interactive
  function _open_hidden_keyserver_iframe() {
    if (!keyserverChan) {
      var doc = window.document;
      var iframe = doc.createElement("iframe");
      iframe.style.display = "none";
      doc.body.appendChild(iframe);
      iframe.src = KEYSERVER + "/communication_iframe";
      keyserverChan = Channel.build({
        window: iframe.contentWindow,
        origin: KEYSERVER,
        scope: "mozks_ni"
      });
    }
  }

  function _generateUserKey(assertion, successCB, failureCB) {
    jwcrypto.addEntropy('TODO: random', 256); // TODO: use entropy provided by BID server

    var passwordKey = storage.getPasswordKey();
    if (passwordKey) {
      var plainUserKey = JSON.stringify(jwcrypto.generateKey(128));
      var wrappedUserKey = jwcrypto.encrypt(plainUserKey, passwordKey);

      keyserverChan.call({
        method: 'set_user_key',
        params: {
          assertion: assertion,
          userkey: wrappedUserKey
        },
        success: function () {
          successCB(plainUserKey);
        },
        error: function (err) {
          failureCB(err);
        }
      });
    } else {
      failureCB('Cannot find a password-derived key for this account.');
    }
  }

  function _unwrapUserKey(wrappedUserKey, successCB, failureCB) {
    var passwordKey = storage.getPasswordKey();
    if (passwordKey) {
      var plainUserKey = jwcrypto.decrypt(wrappedUserKey, passwordKey);
      if (plainUserKey) {
        successCB(plainUserKey);
      } else {
        failureCB('Cannot unwrap the user key for this identity.');
      }
    } else {
      failureCB('Cannot find a password-derived key for this account.');
    }
  }

  function _decryptKey(origin, wrappedKey, userKey, successCB, failureCB) {
    var d = jwcrypto.decrypt(wrappedKey, userKey);
    var bundle = JSON.parse(d);

    if (bundle.audience === origin) {
      successCB(bundle.secretkey);
    } else {
      failureCB('Origin mismatch');
    }
  }

  function _generateAndEncryptKey(origin, userKey, successCB, failureCB) {
    jwcrypto.addEntropy('TODO: random', 256); // TODO: use entropy provided by BID server
    var plainKey = jwcrypto.generateKey(128);
    var bundle = JSON.stringify({audience: origin, secretkey: plainKey});

    var wrappedKey = jwcrypto.encrypt(bundle, userKey);

    successCB(plainKey, wrappedKey);
  }

  function generateAndWrap(identity, origin, successCB, failureCB) {
    _open_hidden_keyserver_iframe();

    if (identity !== storage.getLoggedIn(origin)) {
      failureCB('Invalid identity');
    } else {
      user.getAssertion(identity, KEYSERVER, function (assertion) {
        keyserverChan.call({
          method: 'get_user_key',
          params: {
            assertion: assertion
          },
          success: function (wrappedUserKey) {
            if (!jwcrypto) {
              jwcrypto = require('./lib/jwcrypto.js');
            }

            if (!wrappedUserKey) {
              _generateUserKey(assertion, function (plainUserKey) {
                _generateAndEncryptKey(origin, plainUserKey, successCB, failureCB);
              }, failureCB);
            } else {
              _unwrapUserKey(wrappedUserKey, function (plainUserKey) {
                _generateAndEncryptKey(origin, plainUserKey, successCB, failureCB);
              }, failureCB);
            }
          },
          error: function (err) {
            failureCB(err);
          }
        });
      }, function (err) {
        failureCB(err);
      });
    }
  }

  function unwrap(identity, origin, wrappedKey, successCB, failureCB) {
    _open_hidden_keyserver_iframe();

    if (identity !== storage.getLoggedIn(origin)) {
      failureCB('Invalid identity');
    } else {
      user.getAssertion(identity, KEYSERVER, function (assertion) {
        keyserverChan.call({
          method: 'get_user_key',
          params: {
            assertion: assertion
          },
          success: function (wrappedUserKey) {
            if (!jwcrypto) {
              jwcrypto = require('./lib/jwcrypto.js');
            }

            if (!wrappedUserKey) {
              _generateUserKey(assertion, function (plainUserKey) {
                _decryptKey(origin, wrappedKey, plainUserKey, successCB, failureCB);
              }, failureCB);
            } else {
              _unwrapUserKey(wrappedUserKey, function (plainUserKey) {
                _decryptKey(origin, wrappedKey, plainUserKey, successCB, failureCB);
              }, failureCB);
            }
          },
          error: function (err) {
            failureCB(err);
          }
        });
      }, function (err) {
        failureCB(err);
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
