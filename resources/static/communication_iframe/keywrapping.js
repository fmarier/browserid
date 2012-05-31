/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*globals BrowserID: true, console: true */

BrowserID.KeyWrapping = (function() {
  "use strict";

  var jwcrypto;

  function generateAndWrap(identity, successCB, failureCB) {
    setTimeout(function () {
      failureCB('generateAndWrap not implemented yet');
    }, 0);
  }

  function unwrap(identity, wrappedKey, successCB, failureCB) {
    setTimeout(function () {
      failureCB('unwrap not implemented yet');
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
