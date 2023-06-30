require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const csrf = require('csrf');
const tokens = new csrf();
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');  
const logger = require('./logger');

let app = express();

const PORT = process.env.PORT || 4000;

logger.debug('process.env.NODE_ENV: ' + process.env.NODE_ENV);
logger.debug('process.env.PORT: ' + process.env.PORT);

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

logger.info("OAuth Client created with clientId: " + oauthClient.clientId + ", environment: " + oauthClient.environment);

app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object with clientId: " + req.oauthClient.clientId);
    next();
});

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

app.get('/callback', async (req, res) => {
    try {
        const authResponse = await oauthClient.createToken(req.url);
        req.session.oauth2_token_json = authResponse.getJson();
        res.send(JSON.stringify(req.session.oauth2_token_json, null, 2));
    } catch(e) {
        console.error("Error in /callback: ", e);
        res.status(500).send(`Failed to create token: ${e.message}`);
    }
});

app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await oauthClient.refresh();
        req.session.oauth2_token_json = authResponse.getJson();
        res.send(JSON.stringify(req.session.oauth2_token_json, null, 2));
    } catch(e) {
        console.error("Error in /refreshAccessToken: ", e);
        res.status(500).send(`Failed to refresh token: ${e.message}`);
    }
});

app.get('/getGeneralLedger', async (req, res) => {
    if (!req.session.oauth2_token_json) {
        return res.status(400).send('No OAuth token saved in the session');
    }
    
    oauthClient.setToken(req.session.oauth2_token_json);

    const companyID = oauthClient.getToken().realmId;

    const startDate = '2022-01-01';
    const endDate = '2022-12-31';

    const url = oauthClient.environment == 'sandbox' 
        ? `https://sandbox-quickbooks.api.intuit.com/v3/company/${companyID}/reports/GeneralLedger`
        : `https://quickbooks.api.intuit.com/v3/company/${companyID}/reports/GeneralLedger`;

    const queryParameters = {
        start_date: startDate,
        end_date: endDate,
        columns: 'account_name,subt_nat_amount',
        source_account_type: 'Bank',
        minorversion: 65
    };

    try {
        const authResponse = await oauthClient.makeApiCall({ url: url, method: 'GET', params: queryParameters });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        console.error("Error in /getGeneralLedger: ", e);
        res.status(500).send(`Failed to get general ledger data: ${e.message}`);
    }
});


app.get('/getCompanyInfo', async (req, res) => {
    if (!req.session.oauth2_token_json) {
        return res.status(400).send('No OAuth token saved in the session');
    }
    
    oauthClient.setToken(req.session.oauth2_token_json);

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

app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});
