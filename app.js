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

  app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await tools.refreshTokens(req.session);
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