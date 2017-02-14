
/**
 * Module dependencies.
 */

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var authorizedClientIds = ['papers3', 'papers'];

/**
 * Schema definitions.
 */

mongoose.model('OAuthTokens', new Schema({
  accessToken: { type: String },
  authorizationCode: { type: String},
  accessTokenExpiresAt: { type: Date },
  refreshToken: { type: String },
  refreshTokenExpiresAt: { type: Date },
  scope: { type: String },
  client: { type: Object },
  user: { type: String }
}));

mongoose.model('OAuthClients', new Schema({
  clientId: { type: String },
  clientSecret: { type: String },
  redirectUris: { type: Array },
  name: { type: String },
  id: { type: String },
  grants: { type: Array },
  validScopes: { type: Array }
}));

mongoose.model('OAuthUsers', new Schema({
  userId: { type: String },
  googleAuthEnabled: { type: Boolean, default: true },
  nightscout_uri: { type: String, default: '' }
}));

mongoose.model('OAuthAuthCodes', new Schema({
  authorizationCode: { type: String },
  expiresAt: { type: Date },
  client: { type: Object },
  redirectUri: { type: String },
  user: { type: String },
  scope: { type: String },
  clientOid: { type: String }
}));

var OAuthTokensModel = mongoose.model('OAuthTokens');
var OAuthClientsModel = mongoose.model('OAuthClients');
var OAuthUsersModel = mongoose.model('OAuthUsers');
var OAuthAuthCodesModel = mongoose.model('OAuthAuthCodes');

module.exports.OAuthTokensModel = OAuthTokensModel;
module.exports.OAuthClientsModel = OAuthClientsModel;
module.exports.OAuthUsersModel = OAuthUsersModel;
module.exports.OAuthAuthCodesModel = OAuthAuthCodesModel;

/**
 * Get access token.
 */

module.exports.getAccessToken = function (bearerToken) {
  console.log('in getAccessToken (bearerToken: ' + bearerToken + ')');

  return OAuthTokensModel.findOne({ accessToken: bearerToken }).lean();
};

/**
 * Get client.
 */

module.exports.getClient = function (clientId, clientSecret) {
  console.log(`in getClient (clientId: ${clientId})`);
  if (!clientSecret) {
    return OAuthClientsModel.findOne({clientId: clientId}).exec();
  };
  return OAuthClientsModel.findOne({clientId: clientId, clientSecret: clientSecret}).exec();
};

/**
 * Get refresh token
 */

module.exports.getRefreshToken = function (refreshToken) {
  console.log('in getRefreshToken (refreshToken: ' + refreshToken + ')');

  return OAuthTokensModel.findOne({ refreshToken: refreshToken });
};

/**
 * Add new user
 */

module.exports.addUser = function(userId) {
  const newUser = new OAuthUsersModel({
    userId: userId,
    googleAuthEnabled: true
  });
  return OAuthUsersModel.findOneAndUpdate({userId: userId}, newUser, 
    {upsert: true, setDefaultsOnInsert: true, new: true}).exec();
};

/*
 * Get user.
 */

module.exports.getUser = function (userId) {
  console.log(`in getUser (userId: ${userId})`);
  return OAuthUsersModel.findOne({ userId: userId }).exec();
};

/**
 * Save token.
 */

module.exports.saveToken = function (token, client, user) {
  console.log('in saveToken');

  let newToken = new OAuthTokensModel({
    accessToken: token.accessToken,
    authorizationCode: token.authorizationCode,
    accessTokenExpiresAt: token.accessTokenExpiresAt,
    refreshToken: token.refreshToken,
    refreshTokenExpiresAt: token.refreshTokenExpiresAt,
    scope: token.scope,
    client: client,
    user: user
  });
  return newToken.save();
};

/**
 * Get authorization code.
 */

module.exports.getAuthorizationCode = function (authCode) {
  console.log('in getAuthorizationCode (authorizationCode: ' + authCode + ')');
  return OAuthAuthCodesModel.findOne({ authorizationCode: authCode }).lean();
};

/**
 * Save authorization code.
 */

module.exports.saveAuthorizationCode = function (code, client, userId) {
  console.log(`in saveAuthorizationCode`);

  OAuthClientsModel.findOne({id: client.id}, (err, doc) => {
    const authCode = new OAuthAuthCodesModel({
      authorizationCode: code.authorizationCode,
      expiresAt: code.expiresAt,
      client: doc.toObject(),
      redirectUri: code.redirectUri,
      user: userId,
      scope: code.scope,
      clientOid: doc._id
    });
    return authCode.save();
  });
  // FIX THIS
  // returns - the following return is probably what happens since the 
  // callback will take 100ms or less to execute
  return code;
};

/**
 * Called in `authenticate()` - basic check for scope existance
 * `scope` corresponds to the oauth server configuration option, which
 * could either be a string or boolean true.
 * Since we utilize router-based scope check middleware, here we simply check
 * for scope existance.
 */
module.exports.verifyScope = (token, scope) => {
    console.log(`Verify scope ${scope} in token ${token.accessToken}`);
    if(scope && !token.scope) { return false; }
    return token;
};

// Can be used to sanitize or purely validate requested scope string
module.exports.validateScope = (user, client, scope) => {
  console.log(`Validating requested scope: ${scope}`);

  const validScope = (scope || '').split(' ').filter((key) => {
    return client.validScopes.indexOf(key) !== -1;
  });

  if(!validScope.length) { return false; }
  return validScope.join(' ');
};

// Revoke refresh token after use - note ExpiresAt detail!
module.exports.revokeToken = (token) => {
  console.log(`Revoke token ${token.refreshToken}`);

  // Note: This is normally the DB object instance from getRefreshToken, so
  // just token.delete() or similar rather than the below findIndex.
  /* 
  const idx = db.tokens.findIndex((item) => {
      return item.refreshToken === token.refreshToken;
  });

  db.tokens.splice(idx, 1);
  */
  // Note: Presently, this method must return the revoked token object with
  // an expired date. This is currently being discussed in
  // https://github.com/thomseddon/node-oauth2-server/issues/251
    
  token.refreshTokenExpiresAt = new Date(1984);
  OAuthTokensModel.findOneAndUpdate({_id: token._id}, token, function(err, doc) {
    if (err) {
      console.log(`Error updating token during revokeToken: ${err}`);
      return false;
    }
    return doc;
  });
};

// Revokes the authorization code after use - note ExpiresAt detail!
module.exports.revokeAuthorizationCode = (code) => {
  console.log(`Revoking authorization code ${code.authorizationCode}`);
  const revoke = new Date(1984);
  return OAuthAuthCodesModel.findOneAndUpdate({_id: code._id}, {$set: {expiresAt: revoke}}, {new: true}).lean();
};

// Return nightscout_uri from access token
module.exports.getNsUriFromToken = (accessToken) => {
  // Find userId from access_token and match Nightscout redirect URI
  // Assumes that app.oauth.authenticate() has already returned successfully
  // and validated token
  console.log(`Retrieving Nightscout URL from access_token`);
  let token = OAuthTokensModel.findOne({ accessToken: accessToken }).exec();
  return token.then((doc1) => {
    if (!doc1.user) {
      throw('Token missing user property');
    }
    return OAuthUsersModel.findOne({ userId: doc1.user }).exec();
  })
  .then((doc2) => {
    if (!doc2.nightscout_uri) {
      throw('User missing nightscout_uri property');
    } 
    console.log(`Found nightscout_uri: ${doc2.nightscout_uri}`);
    return doc2.nightscout_uri;
  })
  .catch((e) => {
    console.log(e);
    return false;
  });
};

// Return nightscout_uri from userId
module.exports.getNsUriFromUser = (userId) => {
  // Find userId from access_token and match Nightscout redirect URI
  // Assumes that user has successfully authenticated via Google sign-in
  console.log(`Retrieving Nightscout URL from userId`);
  return OAuthUsersModel.findOne({ userId: userId }).exec();
};

// Update stored nightscout_uri for user
module.exports.setNsUri = (userId, nightscout_uri) => {
  console.log(`Updating Nightscout URL`);    
  return OAuthUsersModel.findOneAndUpdate({userId: userId}, {$set: {nightscout_uri: nightscout_uri}}, {new: true}).exec();
}

// Delete user
module.exports.deleteUser = (userId) => {
  console.log(`Deleting user ${userId}`);
  return OAuthUsersModel.remove({ userId: userId }).exec();
}; 