// routes/index.js

const express = require('express');
const router = express.Router();
const csrf = require('csrf');
const tokens = new csrf();

const { OAuthClient } = require('intuit-oauth');

router.get('/', function(req, res) {
    res.send('Welcome to QuickBooks connection sample app');
});

router.get('/connect', function(req, res) {
    const authUri = req.oauthClient.authorizeUri({
        scope: [req.oauthClient.scopes.Accounting],
        state: tokens.create(req.sessionID),
    });
    res.redirect(authUri);
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
                    console.log(err);
                }
                res.redirect('/');
            });
        })
        .catch(function(e) {
            console.error("Error occurred while creating token: ", e);
        });
});

module.exports = router;
