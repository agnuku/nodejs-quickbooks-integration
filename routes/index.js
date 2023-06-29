const express = require('express');
const router = express.Router();
const csrf = require('csrf');
const tokens = new csrf();
const logger = require('../logger'); // import the logger

const { OAuthClient } = require('intuit-oauth');

router.get('/', function(req, res) {
    logger.info('GET / route hit');
    res.send('Welcome to QuickBooks connection sample app');
});

router.get('/connect', function(req, res) {
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient: ", req.oauthClient);
    
    // Add a null-check for req.oauthClient.scopes
    if (req.oauthClient && req.oauthClient.scopes && req.oauthClient.scopes.Accounting) {
        logger.debug('Authorizing URI with scopes...');
        const authUri = req.oauthClient.authorizeUri({
            scope: [req.oauthClient.scopes.Accounting],
            state: tokens.create(req.sessionID),
        });
        logger.info('Redirecting to: ', authUri);
        res.redirect(authUri);
    } else {
        // Return an error response or handle the case when req.oauthClient.scopes.Accounting is not available
        logger.warn('QuickBooks scope not available, sending 500 response');
        res.status(500).json({ error: 'QuickBooks scope not available' });
    }
});

router.get('/callback', function(req, res) {
    logger.info('GET /callback route hit');
    const parseRedirect = req.url;

    if (!tokens.verify(req.sessionID, req.query.state)) {
        logger.warn('Invalid state, sending error response');
        return res.json({error: 'Invalid state'});
    }

    logger.info('Creating OAuth token...');
    req.oauthClient.createToken(parseRedirect)
        .then(function(authResponse) {
            logger.debug('Token creation successful, saving session...');
            req.session.authResponse = authResponse.json();
            req.session.save(function(err) {
                if(err) {
                    logger.error("Error occurred while saving session: ", err);
                    return;
                }
                logger.info('Session saved successfully, redirecting to /');
                res.redirect('/');
            });
        })
        .catch(function(e) {
            logger.error("Error occurred while creating token: ", e);
            res.status(500).json({ error: 'Error during token creation' });
        });
});

module.exports = router;
