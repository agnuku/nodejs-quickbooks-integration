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

let app = express();

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

// Log only key properties of the oauthClient
logger.info("OAuth Client created with clientId: " + oauthClient.clientId + ", environment: " + oauthClient.environment);

app.use(cors());

app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
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

app.get('/connect', function(req, res) {
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);
    
    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting'],
        state: tokens.create(req.sessionID),
    });
    logger.info('Redirecting to: ' + authUri);
    res.redirect(authUri);
});

app.get('/callback', function (req, res) {
    // Verify anti-forgery
    if (!tokens.verify(req.sessionID, req.query.state)) {
      logger.error('Error - invalid anti-forgery CSRF response!');
      return res.status(403).send('Error - invalid anti-forgery CSRF response!')
    }
  
    // Exchange auth code for access token
    req.oauthClient.createToken(req.url)
      .then(function (token) {
        // Store token - this would be where tokens would need to be
        // persisted (in a SQL DB, for example).
        req.session.token = token;
        req.session.realmId = token.getToken().realmId;
  
        const errorFn = function (e) {
          logger.error('Invalid JWT token!');
          logger.error(e);
          res.redirect('/');
        }
  
        if (token.data.id_token) {
          try {
            // We should decode and validate the ID token
            const decoded = jwt.verify(token.data.id_token, req.oauthClient.clientSecret);
            // If the callback is successful, redirect to /connected
            res.redirect('/connected'); // adjust as needed
          } catch (e) {
            errorFn(e);
          }
        } else {
          // If OpenID isn't used, redirect to /connected
          res.redirect('/connected'); // adjust as needed
        }
      })
      .catch(function (err) {
        logger.error(err);
        res.status(500).send(`Failed to create token: ${err.message}`);
      });
  });
  

app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await oauthClient.refresh();
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(oauth2_token_json);
    } catch(e) {
        console.error("Error in /refreshAccessToken: ", e);
        res.status(500).send(`Failed to refresh token: ${e.message}`);
    }
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
        res.status(500).send(`Failed to get company info: ${e.message}`);
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
        console.error("Error in /getGeneralLedger: ", e);
        res.status(500).send(`Failed to get general ledger: ${e.message}`);
    }
});



app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});