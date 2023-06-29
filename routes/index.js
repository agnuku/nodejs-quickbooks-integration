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

function getGeneralLedger(req) {
    return new Promise((resolve, reject) => {
        const url = `${req.oauthClient.environment === 'sandbox' ? 'https://sandbox-quickbooks.api.intuit.com' : 'https://quickbooks.api.intuit.com'}/v3/company/${req.session.authResponse.realmId}/reports/GeneralLedger?start_date=${calculateStartDate().toISOString().split('T')[0]}&end_date=${new Date().toISOString().split('T')[0]}`;
        const requestObj = {
            url: url,
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${req.session.authResponse.access_token}`
            }
        };

        req.oauthClient.makeApiCall(requestObj).then(response => {
            resolve(response.json);
        }).catch(e => {
            reject(e);
        });
    });
}

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

router.get('/generalledger', function(req, res) {
    getGeneralLedger(req).then(response => {
        res.json(response);
    }).catch(e => {
        res.status(500).json({error: e.message});
    });
});

module.exports = router;
