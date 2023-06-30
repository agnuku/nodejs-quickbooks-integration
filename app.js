require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const csrf = require('csrf');
const tokens = new csrf();
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const logger = require('./logger');

let app = express();

const PORT = process.env.PORT || 4000;

logger.info(`NODE_ENV: ${process.env.NODE_ENV}`);
logger.info(`PORT: ${process.env.PORT}`);

const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.info(`Redirect Uri is set to: ${redirectUri}`);

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.SESSION_SECRET) {
    logger.error('Missing essential configuration. Please check your .env file or environment variables.');
    process.exit(1);
}

let oauthClient = new OAuthClient({
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});

logger.info(`OAuth Client created. clientId: ${oauthClient.clientId}, environment: ${oauthClient.environment}`);

app.use(session({
    secret: process.env.SESSION_SECRET,
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
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);
    
    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting'],
        state: tokens.create(req.sessionID),
    });
    logger.info('Redirecting to: ' + authUri);
    res.redirect(authUri);
});

app.get('/callback', function(req, res) {
    logger.info('GET /callback route hit');
    const parseRedirect = req.protocol + '://' + req.get('host') + req.originalUrl;

    if (!tokens.verify(req.sessionID, req.query.state)) {
        logger.warn('Invalid state, sending error response');
        return res.json({error: 'Invalid state'});
    }

    logger.info('Creating OAuth token...');
    req.oauthClient.createToken(parseRedirect)
        .then(function(authResponse) {
            logger.debug('Token creation successful, saving session...');
            req.session.authResponse = authResponse.getJson(); // Corrected line
            req.session.save(function(err) {
                if(err) {
                    logger.error("Error occurred while saving session: " + err.message);
                    return res.status(500).json({ error: 'Error during session saving' });
                }
                logger.info('Session saved successfully, redirecting to /');
                res.redirect('/');
            });
        })
        .catch(function(e) {
            logger.error("Error occurred while creating token: " + e.message);
            res.status(500).json({ error: 'Error during token creation' });
        });
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
