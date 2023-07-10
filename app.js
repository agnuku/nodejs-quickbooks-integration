const express = require('express');
const session = require('express-session');
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');  
const logger = require('./logger');
const csrf = require('csrf');
const tokens = new csrf(); 
const cors = require('cors');
const Tools = require('./tools/tools');
const request = require('request');
const btoa = require('btoa');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const redisClient = redis.createClient({
  password: 'JME1T2W9hOj7A2vwzuAzLSeh2AgM5lAa',
  host: 'redis-17187.c92.us-east-1-3.ec2.cloud.redislabs.com',
  port: 17187
});

let app = express();

redisClient.on('connect', function () {
    logger.info('Redis client connected');
});

redisClient.on('ready', function () {
    logger.info('Redis client is ready');
});

redisClient.on('reconnecting', function () {
    logger.info('Redis client reconnecting');
});

redisClient.on('end', function () {
    logger.info('Redis client connection ended');
});

redisClient.on('error', function (err) {
    logger.error('Something went wrong with Redis client ' + err);
});

const PORT = process.env.PORT || 4000;

// Define redirectUri based on the environment
const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.debug('redirectUri: ' + redirectUri);

let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});

// Add Tools instantiation
let tools = Tools

app.use(cors());

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 86400000 } // secure: true for HTTPS
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object with clientId: " + req.oauthClient.clientId);
    next();
});

let oauth2_token_json = null;

  app.get('/connect', function(req, res) {
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);

    secret = tokens.secretSync();  // Generate secret
    req.session.csrfSecret = secret; // Store secret in the session

    const state = tokens.create(secret); // Create a CSRF token
    req.session.state = state; // store state parameter in session
    
    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting', 'openid', 'profile', 'email'],
        state: state, // use the generated CSRF token
    });
    logger.info('Redirecting to: ' + authUri);
    res.redirect(authUri);
});
app.get('/callback', function (req, res) {
    // Verify anti-forgery
    if (!tokens.verify(req.session.csrfSecret, req.query.state)) {  // Verify CSRF token
     // Invalid state parameter
     logger.error('Error - invalid state parameter!');
     return res.status(403).send('Error - invalid state parameter!')
    }
    // Exchange auth code for access token
    req.oauthClient.createToken(req.url)
      .then(function (token) {
        // Store token - this would be where tokens would need to be
        // persisted (in a SQL DB, for example).
        req.session.token = token;
        req.session.realmId = token.getToken().realmId;
  
        // If the callback is successful, redirect to /connected
        res.redirect('https://e071-73-68-198-127.ngrok-free.app/connected'); // adjust as needed
      })
      .catch(function (err) {
        logger.error(err);
        res.status(500).send(`Failed to create token: ${err.message}`);
      });
});  

//   app.get('/refreshAccessToken', async (req, res) => {
//     try {
//         const authResponse = await tools.refreshTokens(req.session);
//         oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
//         res.send(oauth2_token_json);
//     } catch(e) {
//         console.error("Error in /refreshAccessToken: ", e);
//         res.status(500).send(`Failed to refresh token: ${e.message}`);
//     }
// });


app.get('/api_call', function (req, res) {
    var token = tools.getToken(req.session)
    if(!token) return res.json({error: 'Not authorized'})
    if(!req.session.realmId) return res.json({
      error: 'No realm ID.  QBO calls only work if the accounting scope was passed!'
    })

    // Set up API call (with OAuth2 accessToken)
    var url = config.api_uri + req.session.realmId + '/companyinfo/' + req.session.realmId
    console.log('Making API call to: ' + url)
    var requestObj = {
      url: url,
      headers: {
        'Authorization': 'Bearer ' + token.accessToken,
        'Accept': 'application/json'
      }
    }

    // Make API call
    request(requestObj, function (err, response) {
      // Check if 401 response was returned - refresh tokens if so!
      tools.checkForUnauthorized(req, requestObj, err, response).then(function ({err, response}) {
        if(err || response.statusCode != 200) {
          return res.json({error: err, statusCode: response.statusCode})
        }

        // API Call was a success!
        res.json(JSON.parse(response.body))
      }, function (err) {
        console.log(err)
        return res.json(err)
      })
    })
});

app.get('/revoke', function (req, res) {
  // Fetch the token from the session
  var token = req.session.token;
  if(!token) {
    console.log('No token found in the session');
    return res.status(401).json({error: 'Not authorized', detailedError: 'No token found in the session'});
  }

  // Access the actual accessToken
  var accessToken = token.getToken().accessToken;
  if(!accessToken) {
    console.log('No access token found in the session token');
    return res.status(401).json({error: 'Not authorized', detailedError: 'No access token found in the session token'});
  }

  // Form the basicAuth string
  var basicAuth = Buffer.from(config.clientId + ':' + config.clientSecret).toString('base64');
  
  var url = config.revoke_uri;

  request({
    url: url,
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + basicAuth,
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: `token=${accessToken}`
  }, function (err, response, body) {
    if(err) {
      console.log('Error when revoking token:', err);
      return res.status(500).json({error: 'Failed to revoke token', detailedError: err.message});
    }
    if(response.statusCode != 200) {
      console.log('Non-200 response when revoking token:', response.statusCode);
      return res.status(response.statusCode).json({error: 'Failed to revoke token', detailedError: 'Received a non-200 HTTP response'});
    }

    // Clear the token from the session
    req.session.token = null;
    req.session.realmId = null;

    console.log('Token successfully revoked');
    res.json({response: "Revoke successful"});
  });
});


app.get('/api_call/refresh', function (req, res) {
    var token = tools.getToken(req.session)
    if(!token) return res.json({error: 'Not authorized'})

    tools.refreshTokens(req.session).then(function(newToken) {
      // We have new tokens!
      res.json({
        accessToken: newToken.accessToken,
        refreshToken: newToken.refreshToken
      })
    }, function(err) {
      // Did we try to call refresh on an old token?
      console.log(err)
      res.json(err)
    })
});


app.get('/getCompanyInfo', async (req, res) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/companyinfo/${companyID}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: finalUrl });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        console.error("Error in /getCompanyInfo: ", e);

        if (e.status == 401) {
            // Unauthorized error, let's refresh the token
            tools.checkForUnauthorized(req, requestObj, err, e)
                .then(({err, response}) => {
                    // Retry the api call
                })
                .catch((err) => {
                    res.status(500).send(`Failed to refresh token: ${err.message}`);
                });
        } else {
            res.status(500).send(`Failed to get company info: ${e.message}`);
        }
    }
});

app.get('/getGeneralLedger', async (req, res) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/reports/GeneralLedger`;

    // Use the query parameters from the request
    const queryParams = req.query;

    const urlWithParams = `${finalUrl}?${new URLSearchParams(queryParams).toString()}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: urlWithParams });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        console.error("Error in /getCompanyInfo: ", e);

        if (e.status == 401) {
            // Unauthorized error, let's refresh the token
            tools.checkForUnauthorized(req, requestObj, err, e)
                .then(({err, response}) => {
                    // Retry the api call
                })
                .catch((err) => {
                    res.status(500).send(`Failed to refresh token: ${err.message}`);
                });
        } else {
            res.status(500).send(`Failed to get company info: ${e.message}`);
        }
    }
});



app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});