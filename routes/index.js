const express = require('express');
const router = express.Router();
const csrf = require('csrf');
const tokens = new csrf();
const logger = require('../logger'); 

const { OAuthClient } = require('intuit-oauth');

router.get('/generalledger', function(req, res) {
    logger.info('GET /generalledger route hit');
    
    if(!req.session || !req.session.authResponse || !req.session.authResponse.realmId) {
        logger.warn('Session, auth response, or realmId not available');
        return res.json({ error: 'Session, auth response, or realmId not available' });
    }

    const oauthClient = req.oauthClient;
    const companyID = req.session.authResponse.realmId;

    const startDate = '2022-01-01';
    const endDate = '2022-12-31';

    const url = `${oauthClient.environment == 'sandbox' ? 'https://sandbox-quickbooks.api.intuit.com' : 'https://quickbooks.api.intuit.com'}/v3/company/${companyID}/reports/GeneralLedger`;

    const queryParameters = {
        start_date: startDate,
        end_date: endDate,
        columns: 'account_name,subt_nat_amount',
        source_account_type: 'Bank',
        minorversion: 65
    };

    const requestUri = oauthClient.token.getToken().token_type + ' ' + oauthClient.token.getToken().access_token;
    const authHeaders = {
        headers: {
            Authorization: requestUri,
            Accept: 'application/json'
        }
    };

    oauthClient
    .makeApiCall({url: url, method: 'GET', params: queryParameters, headers: authHeaders})
    .then(function(authResponse){
        logger.debug("General ledger response: " + JSON.stringify(authResponse));
        res.json(authResponse);
    })
    .catch(function(e){
        logger.error("Error occurred while fetching general ledger data: " + e.message);
        res.status(500).json({ error: 'Error during general ledger data retrieval' });
    });
});

router.get('/companyinfo', function(req, res) {
    logger.info('GET /companyinfo route hit');

    if(!req.session || !req.session.authResponse || !req.session.authResponse.realmId) {
        logger.warn('Session, auth response, or realmId not available');
        return res.json({ error: 'Session, auth response, or realmId not available' });
    }

    const oauthClient = req.oauthClient;
    const companyID = req.session.authResponse.realmId;

    const url = `${oauthClient.environment == 'sandbox' ? 'https://sandbox-quickbooks.api.intuit.com' : 'https://quickbooks.api.intuit.com'}/v3/company/${companyID}/companyinfo/${companyID}`;

    const requestUri = oauthClient.token.getToken().token_type + ' ' + oauthClient.token.getToken().access_token;
    const authHeaders = {
        headers: {
            Authorization: requestUri,
            Accept: 'application/json'
        }
    };

    oauthClient
    .makeApiCall({url: url, method: 'GET', headers: authHeaders})
    .then(function(authResponse){
        logger.debug("Company info response: " + JSON.stringify(authResponse));
        res.json(authResponse);
    })
    .catch(function(e){
        logger.error("Error occurred while fetching company info: " + e.message);
        res.status(500).json({ error: 'Error during company info retrieval' });
    });
});

router.get('/', function(req, res) {
    logger.info('GET / route hit');
    res.send('Welcome to Quickbooks Integration');
});

router.get('/connect_to_quickbooks', function(req, res) {
    logger.info('GET /connect_to_quickbooks route hit');
    req.session.csrfToken = tokens.create(req.sessionID);
    res.redirect(oauthClient.authorizeUri({scope:[OAuthClient.scopes.Accounting],state:req.session.csrfToken}));
});

router.get('/callback', function(req, res) {
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
            logger.debug('Auth response: ', authResponse.getJson()); // Added this line to log auth response
            req.session.authResponse = authResponse.getJson();
            req.session.save(function(err) {
                if (err) {
                    logger.error('Session saving error: ', err);
                    return res.json({ error: 'Could not save session' });
                }
                logger.info('Session saved successfully');
                return res.redirect('/connected');
            });
        })
        .catch(function(e) {
            logger.error('Token creation error: ', e);
            return res.json({ error: 'Could not create token' });
        });
});

module.exports = router;
