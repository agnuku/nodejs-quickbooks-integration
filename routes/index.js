const express = require('express');
const router = express.Router();
const csrf = require('csrf');
const tokens = new csrf();
const logger = require('../logger'); // import the logger

const { OAuthClient } = require('intuit-oauth');

router.get('/', function(req, res) {
    res.send('Welcome to QuickBooks connection sample app');
});

router.get('/connect', function(req, res) {
    logger.debug("In /connect route, req.oauthClient: ", req.oauthClient);
    
    // Add a null-check for req.oauthClient.scopes
    if (req.oauthClient && req.oauthClient.scopes && req.oauthClient.scopes.Accounting) {
        const authUri = req.oauthClient.authorizeUri({
            scope: [req.oauthClient.scopes.Accounting],
            state: tokens.create(req.sessionID),
        });
        res.redirect(authUri);
    } else {
        // Return an error response or handle the case when req.oauthClient.scopes.Accounting is not available
        res.status(500).json({ error: 'QuickBooks scope not available' });
    }
});

router.get('/callback', function(req, res) {
    const parseRedirect = req.url;

    if (!tokens.verify(req.sessionID, req.query.state)) {
        return res.json({error: 'Invalid state'});
    }

    req.oauthClient.createToken(parseRedirect)
        .then(function(authResponse) {
            req.session.authResponse = authResponse.json();
            req.session.save(function(err) {
                if(err) {
                    logger.error("Error occurred while saving session: ", err);
                }
                res.redirect('/');
            });
        })
        .catch(function(e) {
            logger.error("Error occurred while creating token: ", e);
        });
});

module.exports = router;
