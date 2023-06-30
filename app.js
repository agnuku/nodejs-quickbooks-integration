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

logger.info(`NODE_ENV: ${process.env.NODE_ENV}`);
logger.info(`PORT: ${process.env.PORT}`);

const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.info(`Redirect Uri is set to: ${redirectUri}`);

let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});

logger.info(`OAuth Client created. clientId: ${oauthClient.clientId}, environment: ${oauthClient.environment}`);

app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    next();
});

app.get('/connect', function(req, res) {
    logger.info('Connecting to the Auth server');
    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting'],
        state: tokens.create(req.sessionID),
    });
    logger.info(`Redirecting to: ${authUri}`);
    res.redirect(authUri);
});

app.get('/callback', async (req, res) => {
    try {
        const authResponse = await req.oauthClient.createToken(req.url);
        req.session.oauth2_token_json = authResponse.getJson();
        logger.info(`New token received and stored: ${JSON.stringify(req.session.oauth2_token_json)}`);
        res.send(JSON.stringify(req.session.oauth2_token_json, null, 2));
    } catch(e) {
        logger.error(`Error occurred in callback: ${e}`);
        res.status(500).send(`Failed to create token: ${e.message}`);
    }
});

app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await req.oauthClient.refresh();
        req.session.oauth2_token_json = authResponse.getJson();
        logger.info(`Token refreshed and stored: ${JSON.stringify(req.session.oauth2_token_json)}`);
        res.send(JSON.stringify(req.session.oauth2_token_json, null, 2));
    } catch(e) {
        logger.error(`Error occurred in refreshAccessToken: ${e}`);
        res.status(500).send(`Failed to refresh token: ${e.message}`);
    }
});

app.get('/getCompanyInfo', async function(req, res){
    try {
        if (!req.session.oauth2_token_json) {
            return res.status(400).send('No OAuth token saved in the session');
        }

        req.oauthClient.setToken(req.session.oauth2_token_json);
        const companyID = req.oauthClient.getToken().realmId;
        const url = req.oauthClient.environment == 'sandbox' 
            ? `https://sandbox-quickbooks.api.intuit.com/v3/company/${companyID}/companyinfo/${companyID}`
            : `https://quickbooks.api.intuit.com/v3/company/${companyID}/companyinfo/${companyID}`;

        logger.info(`Requesting CompanyInfo from URL: ${url}`);
        
        const authResponse = await req.oauthClient.makeApiCall({url: url});

        logger.info(`CompanyInfo Response: ${JSON.stringify(authResponse)}`);
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        logger.error(`Error occurred in getCompanyInfo: ${e}`);
        res.status(500).send(e.toString());
    }
});


app.get('/getGeneralLedger', async (req, res) => {
    try {
        if (!req.session.oauth2_token_json) {
            return res.status(400).send('No OAuth token saved in the session');
        }

        req.oauthClient.setToken(req.session.oauth2_token_json);
        const companyID = req.oauthClient.getToken().realmId;
        const startDate = '2022-06-29';
        const endDate = '2023-06-29';
        const url = req.oauthClient.environment == 'sandbox' 
            ? `https://sandbox-quickbooks.api.intuit.com/v3/company/${companyID}/reports/GeneralLedger`
            : `https://quickbooks.api.intuit.com/v3/company/${companyID}/reports/GeneralLedger`;

        const queryParameters = {
            start_date: startDate,
            end_date: endDate,
            columns: 'account_name,subt_nat_amount',
        };

        logger.info(`Requesting GeneralLedger from URL: ${url} with parameters: ${JSON.stringify(queryParameters)}`);

        const authResponse = await req.oauthClient.makeApiCall({ url: url, method: 'GET', params: queryParameters });
        logger.info(`GeneralLedger Response: ${JSON.stringify(authResponse)}`);
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        logger.error(`Error occurred in getGeneralLedger: ${e}`);
        res.status(500).send(`Failed to get general ledger data: ${e.message}`);
    }
});

app.listen(PORT, function(){
    logger.info(`Server started on port ${PORT}`);
});
