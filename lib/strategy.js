// Load modules.
var passport = require('passport-strategy')
  , util = require('util')
  , discourse_sso = require("./discourse-sso.js");

var log_debug = function () {

}

var log_debug_ON = function () {
  if (global.log)
    log.debug.apply(log, arguments);
  else {
    var args = Array.prototype.slice.call(arguments);
    args.unshift("DEBUG [passport-discourse]");
    console.log.apply(console, args);
  }
};

var Provider = null;

/**
 * `Strategy` constructor.
 *
 * The Discourse authentication strategy authenticates requests by delegating to
 * a Discourse site using the Discourse SSO protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `secret`        your Discourse connect provider secret
 *   - `discourse_url` your Discourse site base URL
 *   - `callbackURL`   URL to which Discourse will redirect the user after granting authorization
 *   - `debug`         enable additional log output
 *
 * Examples:
 *     passport.use(new DiscourseStrategy({
 *         secret: 'shhh-its-a-secret',
 *         discourse_url: 'https://discourse.example.net',
 *         callback_url: 'https://www.example.net/auth/discourse/callback',
 *         debug: True
 *       },
 *       function(req, accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  if (typeof verify !== 'function') throw new TypeError("passport-discourse requires a verify callback");

  if (options.debug) {
    log_debug = log_debug_ON;
  }

  if (!Provider) Provider = new discourse_sso(options);

  passport.Strategy.call(this);
  this.name = 'discourse';

  this.verify_cb = verify;
}

// Inherit from `Strategy`.
util.inherits(Strategy, passport.Strategy);

/**
 * Retrieve user profile from Discourse.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `discourse`
 *   - `id`               the user's Discourse ID number
 *   - `username`         the user's Discourse username
 *   - `email`            the user's email address 
 *   - `displayName`      the user's full name
 *   - `avatar`           the URL of the profile avatar for the user on Discourse
 *   - `groups`           the user's groups on Discourse (comma separated list as a string)
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
// Strategy.prototype.userProfile = function(accessToken, done) {
//   var self = this;
// }

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  if (!options) options = {};
  // options._passportReq = {
  //   success: self.success,
  //   fail: self.fail
  // };

  // console.log("*************************************************");
  // console.dir(this);
  // console.log(req.originalUrl);
  // console.log("*************************************************");

  function _verify_discourse_sso(req, res) {
    log_debug("VERIFY -------------------------------------------------", req.originalUrl);
    log_debug("req:", req);
    var ret = Provider.validateAuth(req, req.originalUrl);
    var profile = {};
    if (ret) {


      /*
      If the request succeeded in authenticating a user, the result payload will contain user credentials/information:

external_id: (integer) Discourse id
username: (string) username/handle
name: (string) user’s real name
email: (string) email address
avatar_url: (string) URL to the original, unscaled image as uploaded by user
admin: (boolean) true if user is an Admin, otherwise false
moderator: (boolean) true if user is a Moderator, otherwise false
groups: (string) comma-separated list of groups (by name) to which the user belongs
       */

      profile.provider = 'discourse';
      // This ID breaks Wiki.JS authentication
      // profile.id = ret.external_id;
      profile.external_id = ret.external_id;
      profile.username = ret.username;
      profile.email = ret.email;
      profile.realName = ret.name;
      profile.avatar = ret.avatar_url;
      profile.groups = ret.groups;
      profile.admin = ret.admin;
      profile.moderator = ret.moderator;
    }
    self.verify_cb(req, null, null, profile, function (err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail("Failed to validate user"); }

      info = info || {};
      self.success(user, info);
    });
  }

  var s = req.originalUrl
  log_debug('authenticate', s);
  if (s.length >= 1 && s.includes('sso=')) {
    _verify_discourse_sso(req);
  } else {
    log_debug('authenticate-headers', req.headers);
    var auth_req = Provider.generateAuthRequest(req, options).then(function (ret) {
      log_debug("redirect to:", ret.url_redirect);
      log_debug("REDIRECT ------------------------------------------------");
      self.redirect(ret.url_redirect);
    });
  }
}

// Expose constructor.
module.exports = Strategy;
