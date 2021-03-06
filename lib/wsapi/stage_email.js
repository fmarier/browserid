/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
db = require('../db.js'),
wsapi = require('../wsapi.js'),
httputils = require('../httputils'),
logger = require('../logging.js').logger,
email = require('../email.js');

/* First half of account creation.  Stages a user account for creation.
 * this involves creating a secret url that must be delivered to the
 * user via their claimed email address.  Upon timeout expiry OR clickthrough
 * the staged user account transitions to a valid user account
 */

exports.method = 'post';
exports.writes_db = true;
exports.authed = 'assertion';
exports.args = ['email','site'];
exports.i18n = true;

exports.process = function(req, res) {
  db.lastStaged(req.body.email, function (last) {
    if (last && (new Date() - last) < config.get('min_time_between_emails_ms')) {
      logger.warn('throttling request to stage email address ' + req.body.email + ', only ' +
                  ((new Date() - last) / 1000.0) + "s elapsed");
      return httputils.forbidden(res, "throttling.  try again later.");
    }

    try {
      // on failure stageEmail may throw
      db.stageEmail(req.session.userid, req.body.email, function(secret) {
        var langContext = wsapi.langContext(req);

        // store the email being added in session data
        req.session.pendingAddition = secret;

        res.json({ success: true });

        // let's now kick out a verification email!
        email.sendAddAddressEmail(req.body.email, req.body.site, secret, langContext);
      });
    } catch(e) {
      // we should differentiate tween' 400 and 500 here.
      httputils.badRequest(res, e.toString());
    }
  });
};
