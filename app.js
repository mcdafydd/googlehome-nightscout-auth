const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const OAuthServer = require('express-oauth-server');
const mongoose = require('mongoose');
const model = require('./models');
const ActionsSdkAssistant = require('actions-on-google').ActionsSdkAssistant;
const GoogleAuth = require('google-auth-library');
const validUrl = require('valid-url');
const path = require('path');
const Promise = require('bluebird');

let mongouri = process.env.MONGODB_URI;

// See http://mongoosejs.com/docs/promises.html
mongoose.Promise = Promise;

process.env['DEBUG'] = 'actions-on-google:*';

// Makes connection asynchronously. Mongoose will queue up database
// operations and release them when the connection is complete.
mongoose.connect(mongouri, function (err) {
  if (err) {
    console.log(`ERROR connecting to mongoDB: ${err}`);
  } else {
    console.log('Succeeded connection to mongoDB');
  }
});

let app = express();
let store = new MongoDBStore(
  {
    uri: mongouri,
    collection: 'cookies'
  });

// Catch errors 
store.on('error', function (err) {
  assert.ifError(err);
  assert.ok(false);
});

// Serve static web app files
app.use('/public', express.static(path.join(__dirname, 'public')));

app.oauth = new OAuthServer({
  grants: ['authorization_code', 'refresh_token'],
  model: require('./models'),
  continueMiddleware: false,
  scope: 'nightscout_uri',
  addAcceptedScopesHeader: true,
  addAuthorizedScopesHeader: true
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  },
  store: store,
  resave: true,
  saveUninitialized: true
}))

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
// https://oauth-redirect.googleusercontent.com/r/actions-153005
// https%3A%2F%2Fdevelopers.google.com%2Foauthplayground

app.get('/oauth/auth', (req, res) => {
  // Verify request parameters are available and valid, don't update session
  // otherwise
  if (Object.prototype.hasOwnProperty.call(req.query, 'state') &&
    Object.prototype.hasOwnProperty.call(req.query, 'scope') &&
    Object.prototype.hasOwnProperty.call(req.query, 'client_id') &&
    Object.prototype.hasOwnProperty.call(req.query, 'redirect_uri') &&
    Object.prototype.hasOwnProperty.call(req.query, 'response_type')) {
    console.log('GET /oauth/auth: Saving query parameters to session state');
    req.session.query = {
      state: req.query.state,
      scope: req.query.scope,
      client_id: req.query.client_id,
      redirect_uri: req.query.redirect_uri,
      response_type: req.query.response_type
    };
    // After successfully validating OAuth2 opening request, handle user
    // authentication
    if (!req.session.hasOwnProperty('userId')) {
      console.log('GET /oauth/auth: User not authenticated, redirecting to /public/login.html');
      res.redirect('/public/login.html');
      return;
    }
    else {
      console.log('GET /oauth/auth: User already authenticated, redirecting to /oauth/acceptScope');
      res.redirect('/oauth/acceptScope');
      return;
    }
  }
  else {
    res.status(400).send('Bad request');
  };
  return;
});

app.get('/oauth/acceptScope', (req, res) => {
  // If user is authenticated and req.query is an empty object, assume that
  // user is returning here to accept scope
  if (req.session.userId && Object.keys(req.query).length === 0 && req.session.hasOwnProperty('query')) {
    const client = model.getClient(req.session.query.client_id, null);
    client.then((doc) => {
      if (!doc.name) { res.status(403).send('No such client'); }
      // Prompt user based on query scope if present
      res.send(body = `<html><body><h1>Grant access to "${doc.name}"?</h1>`
        + `<p>The application requests access to ${req.session.query.scope}</p>`
        + '<form action="/oauth/auth" method="post">'
        + '<input type="submit" value="Grant access"></form></body></html>'
      );
    });
  }
  else {
    res.status(400).send('Bad request');
  }
});

app.post('/oauth/auth', (req, res, next) => {
  // Process access/refresh token requests
  if (!req.session.userId) {
    console.log('POST /oauth/auth: User not authenticated, redirecting to /public/login.html');
    res.redirect('/public/login.html');
    return;
  }
  req.body = req.session.query;
  req.body.user_id = req.session.userId;
  delete req.session.query;
  return next();
}, app.oauth.authorize({
  authenticateHandler: {
    handle: (req, res) => {
      // req.session.userId is only set if validateIdToken() succeeds
      // do we need to validate userId in db?
      return req.body.user_id;
    }
  }
}));

app.use('/oauth/token', app.oauth.token());
// For all other requests - user must have valid token or login
//app.use('/', app.oauth.authenticate(), function (req, res) {
//  res.redirect(302, 'https://c5040abb.ngrok.io');
//});

app.post('/login', (req, res, next) => {
  authnUser(req, res, next);
}, (req, res) => {
  // If we were sent here from oauth grant page, redirect back
  if (req.session.hasOwnProperty('query')) {
    console.log('Redirecting back to grant dialog');
    // String 'oauthUser' will instruct login.html to add meta refresh tag
    // to document to continue the OAuth2 authentication flow
    res.send('oauthUser');
    return;  // exit request processing
  }
  // If not, this was likely reached from the Google auth login.html POST
  let respText = res.locals.email ? res.locals.email : 'nobody';
  res.send(respText);
});

app.get('/logout', (req, res) => {
  req.session.userId = null;
  res.redirect('/public/login.html');
});

// If user signs in via a browser, assume they want to update their nightscout_uri
app.get('/private/user', (req, res, next) => {
  console.log('Present user with nightscout_uri update form');
  if (!req.session.userId) {
    res.status(403).send('Authentication required');
    return next();
  };
  const promise = model.getNsUriFromUser(req.session.userId);
  promise.then((doc) => {
    if (typeof doc.nightscout_uri === undefined) {
      throw ('User missing nightscout_uri property');
    }
    console.log(`Found nightscout_uri: ${doc.nightscout_uri}`);
    res.send('<!DOCTYPE html><html><body><form action="/private/update" method="post">'
      + '<h1>Update your Nightscout URL</h1>'
      + '<p>Inserting a valid URL here will allow your Google Home to answer "Talk '
      + 'to night scout" with data from your Nightscout site.</p>'
      + '<p>Current URL = <b>' + doc.nightscout_uri + '</b></p>'
      + '<input type="url" name="nightscout_uri" '
      + 'value="' + doc.nightscout_uri + '">'
      + '<input type="submit" value="Update URL">'
      + '</form><p><a href="/">Return to login page</a></p></body></html>'
    );
  })
    .catch((e) => {
      console.log(e);
      return false;
    });
});

// Delete signed in user account and data from database
// Remove session
app.delete('/user', (req, res, next) => {
  if (!req.session.userId) {
    res.status(403).send('Authentication required');
    return next();
  };
  const promise = model.deleteUser(req.session.userId);
  promise.then((doc) => {
    // prevent error response because we're destroying the session at the same
    // time we're building a response
    const userId = req.session.userId;
    if (!doc) {
      res.status(400).send(`No users found matching userId ${userId}`);
    }
    res.status(200).send(`Successfully deleted user ${userId}`);
    req.session.destroy();
  })
    .catch((err) => {
      res.status(400).send(`Error in update request: ${err}`);
    });
});

// Update db with new nightscout_uri
app.post('/private/update', (req, res) => {
  console.log('Updating user nightscout_uri');
  // Validate user-supplied input before saving
  if (validUrl.isUri(req.body.nightscout_uri)) {
    console.log('User supplied valid URI');
    const dbres = model.setNsUri(req.session.userId, req.body.nightscout_uri);
    dbres.then((doc) => {
      if (!doc) {
        res.status(400).send('Could not update nightscout_uri'
          + '<meta http-equiv="refresh" content="3; url=/private/user">');
      }
      res.status(200).send('Successfully updated nightscout_uri'
        + '<meta http-equiv="refresh" content="3; url=/private/user">');
    })
      .catch((err) => {
        res.status(400).send(`Error in update request: ${err}`
          + '<meta http-equiv="refresh" content="3; url=/private/user">');
      });
  } else {
    console.log('User supplied invalid URI');
    res.status(400).send('Invalid URL'
      + '<meta http-equiv="refresh" content="3; url=/private/user">');
  }
});

// Redirect unauthenticated browser sessions to /public/login.html
app.get('/', (req, res) => {
  console.log('redirecting to login page');
  res.redirect(302, '/public/login.html');
});

// If client has a valid access_token, redirect google assistant to nightscout_uri
app.post('/', (req, res, next) => {
  /* Google Home sends POST requests in JSON with a user object containing the 
   * the user_id and access_token.
   * Extract the access_token and add it asa bearer token in the request headers
   * before passing to OAuth middleware
   */
  var access_token = '';

  // Google
  if (req.body.hasOwnProperty('user')) {
    res.locals.access_token = req.body.user.access_token;
    res.locals.requestor = 'google';
  };
  // API.AI - wraps original Google Assistant request and adds additional properties
  if (req.body.hasOwnProperty('originalRequest')) {
    res.locals.access_token = req.body.originalRequest.data.user.access_token;
    res.locals.requestor = 'apiai';
  };
  // add error checking
  req.headers['Authorization'] = 'Bearer ' + res.locals.access_token;
  next();
}, app.oauth.authenticate(), (req, res) => {
  const assistant = new ActionsSdkAssistant({ request: req, response: res });
  const promise = model.getNsUriFromToken(res.locals.access_token);
  promise.then((nightscout_uri) => {
    if (!nightscout_uri) {
      let speech = 'It looks like your Night scout URL isn\'t set. '
        + 'Please login to the Night Scout foundation web site and add it to '
        + 'your Google Home configuration settings.';
      if (res.locals.requestor === 'google') {
        assistant.tell(speech);
      }
      if (res.locals.requestor === 'apiai') {
        return res.json({
          speech: speech,
          displayText: speech,
          source: 'nightscout-apiai-webhook'
        });
      }
      res.status(400).send('Night scout URL missing from user settings');
    };
    if (!validUrl.isUri(nightscout_uri)) {
      let speech = 'It looks like your Night scout URL is not valid. '
        + 'Please login to the Night Scout foundation web site and add the '
        + 'correctly formatted website address to your Google Home '
        + 'configuration settings.';
      if (res.locals.requestor === 'google') {
        assistant.tell(speech);
      }
      if (res.locals.requestor === 'apiai') {
        return res.json({
          speech: speech,
          displayText: speech,
          source: 'nightscout-apiai-webhook'
        });
      }
      res.status(400).send('Night scout URL is invalid');
    }
    res.redirect(302, nightscout_uri);
  })
});

function authnUser(req, res, next) {
  // Verify Google ID token
  let auth = new GoogleAuth;
  let idtoken = req.body.idtoken;
  let client = new auth.OAuth2(process.env.OAUTH_CLIENT_ID, '', '');
  client.verifyIdToken(
    idtoken,
    process.env.OAUTH_CLIENT_ID,
    // Or, if multiple clients access the backend:
    //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3],
    function (err, login) {
      console.log('Google verifyIdToken callback');
      if (login) {
        let payload = login.getPayload();
        let userId = payload['sub'];
        console.log(`setting userId session ${userId}`);
        req.session.userId = userId;
        res.locals.email = payload['email'];
        // If request specified a G Suite domain:
        //let domain = payload['hd'];
        // If userId doesn't exist, create new user
        const promise = model.getUser(userId);
        promise.then((doc) => {
          if (doc === null) {
            throw (`User ${userId} doesn't exist`);
          }
          console.log(`Retrieved record for user ${userId}`);
          return next();
        }).catch((err) => {
          // user doesn't exist
          console.log(`Creating new user for ${userId}`);
          const promise = model.addUser(userId);
          promise.then((doc) => {
            console.log(`Added new user: ${userId}`);
            return next();
          })
            .catch((err) => {
              console.log(`Error trying to add user ${userId}: ${err}`);
              return res.status(400).send('Bad request - unable to add new user');
            });
        });
      }
      else {
        console.log(`Google verifyIdToken error: ${err}`);
        return next(err);
      }
      return next();
    });
}

module.exports = app;
