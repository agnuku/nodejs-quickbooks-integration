const express = require('express');
const router = express.Router();
const csrf = require('csrf');
const tokens = new csrf();
const logger = require('../logger'); // import the logger

const { OAuthClient } = require('intuit-oauth');

function calculateStartDate() {
    let date = new Date();
    date.setFullYear(date.getFullYear() - 1);
    return date;
}

router.get('/generalledger', function(req, res) {
    logger.info('GET /generalledger route hit');
    if(!req.session || !req.session.authResponse) {
        logger.warn('Session or auth response not available');
        return res.json({ error: 'Session or auth response not available' });
    }
    const oauthClient = req.oauthClient;
    const companyID = req.session.authResponse.realmId;
    
    const startDate = calculateStartDate();
    const endDate = new Date();

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

router.get('/', function(req, res) {
    logger.info('GET / route hit');
    res.send('Welcome to QuickBooks connection sample app');
});

router.get('/connect', function(req, res) {
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);
    
    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting'],
        state: tokens.create(req.sessionID),
    });
    logger.info('Redirecting to: ' + authUri);
    res.redirect(authUri);
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

module.exports = router;
