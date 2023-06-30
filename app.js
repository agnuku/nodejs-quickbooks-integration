require('dotenv').config();
const express = require('express');
const session = require('express-session');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');  
const logger = require('./logger');
const csrf = require('csrf');
const tokens = new csrf(); 
const { check, validationResult } = require('express-validator');

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
        req.session.oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2); 
        res.send(req.session.oauth2_token_json);
    } catch(e) {
        logger.error("Error in /callback: ", e);
        res.status(500).json({
            success: false,
            message: `Failed to create token: ${e.message}`,
            stack: process.env.NODE_ENV === 'development' ? e.stack : undefined,
        });
    }
});

app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await oauthClient.refresh();
        req.session.oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(req.session.oauth2_token_json);
    } catch(e) {
        logger.error("Error in /refreshAccessToken: ", e);
        res.status(500).json({
            success: false,
            message: `Failed to refresh token: ${e.message}`,
            stack: process.env.NODE_ENV === 'development' ? e.stack : undefined,
        });
    }
});

app.get('/getCompanyInfo', async (req, res) => {
    let client = new OAuthClient({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        environment: 'sandbox',
        redirectUri: redirectUri,
    });
    client.setToken(JSON.parse(req.session.oauth2_token_json));
    const companyID = client.getToken().realmId;
    const url = client.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/companyinfo/${companyID}`;

    try {
        const authResponse = await client.makeApiCall({ url: finalUrl });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        logger.error("Error in /getCompanyInfo: ", e);
        res.status(500).json({
            success: false,
            message: `Failed to get company info: ${e.message}`,
            stack: process.env.NODE_ENV === 'development' ? e.stack : undefined,
        });
    }
});

app.get('/getGeneralLedger', [
    check('start_date').isDate(),
    check('end_date').isDate(),
    check('accounting_method').isIn(['Cash', 'Accrual']),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    let client = new OAuthClient({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        environment: 'sandbox',
        redirectUri: redirectUri,
    });
    client.setToken(JSON.parse(req.session.oauth2_token_json));
    const companyID = client.getToken().realmId;
    const url = client.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/reports/GeneralLedger`;

    const queryParams = req.query;
    const urlWithParams = `${finalUrl}?${new URLSearchParams(queryParams).toString()}`;

    try {
        const authResponse = await client.makeApiCall({ url: urlWithParams });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        logger.error("Error in /getGeneralLedger: ", e);
        res.status(500).json({
            success: false,
            message: `Failed to get general ledger: ${e.message}`,
            stack: process.env.NODE_ENV === 'development' ? e.stack : undefined,
        });
    }
});

app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});  

