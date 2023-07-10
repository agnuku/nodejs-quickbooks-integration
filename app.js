require('dotenv').config();
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

let app = express();
let secret;

// Get the port from environment or use 4000 as default
const PORT = process.env.PORT || 4000;

logger.debug('process.env.NODE_ENV: ' + process.env.NODE_ENV);
logger.debug('process.env.PORT: ' + process.env.PORT);

// Define redirectUri based on the environment
const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.debug('redirectUri: ' + redirectUri);

// Instantiate new client
let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});

// Add Tools instantiation
let tools = Tools

// Log only key properties of the oauthClient
logger.info("OAuth Client created with clientId: " + oauthClient.clientId + ", environment: " + oauthClient.environment);

app.use(cors());

app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 'secure: true' for HTTPS, 'false' for HTTP
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set oauthClient in middleware so we can access it in routes
app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object with clientId: " + req.oauthClient.clientId);
    next();
});

let oauth2_token_json = null; // Add this line

// app.get('/test', function(req, res) {
//     req.session.testVar = 'Hello World';
//     res.send('Test variable set');
//   });
  
//   app.get('/check', function(req, res) {
//     if (req.session.testVar) {
//       res.send('Test variable: ' + req.session.testVar);
//     } else {
//       res.send('No test variable found');
//     }
//   });

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

app.get('/api_call/revoke', function (req, res) {
    // Fetch the token from the session
    var token = req.session.token;
    if(!token) return res.json({error: 'Not authorized'})

    // Form the basicAuth string
    var basicAuth = btoa(config.clientId + ':' + config.clientSecret);
    
    var url = config.revoke_uri;

    request({
      url: url,
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + basicAuth,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        'token': token.accessToken
      })
    }, function (err, response, body) {
      if(err || response.statusCode != 200) {
        return res.json({error: err, statusCode: response.statusCode})
      }

      // Clear the token from the session
      req.session.token = null;
      req.session.realmId = null;

      console.log('Token successfully revoked');
      res.json({response: "Revoke successful"})
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