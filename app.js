require('dotenv').config();
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');
const logger = require('./logger');
const csrf = require('csrf');
const tokens = new csrf();
const { isValid } = require('date-fns');
const { check, validationResult } = require('express-validator');

let client;

client = redis.createClient({
    password: 'JME1T2W9hOj7A2vwzuAzLSeh2AgM5lAa',
    socket: {
        host: 'redis-17187.c92.us-east-1-3.ec2.cloud.redislabs.com',
        port: 17187
    }
});

client.connect().then(() => {
    console.log('Redis client connected');
    client.on('connect', function () {
        console.log('Redis client connected');
    });

    client.on('ready', function () {
        console.log('Redis client is ready');
    });

    client.on('reconnecting', function () {
        console.log('Redis client reconnecting');
    });

    client.on('end', function () {
        console.log('Redis client connection ended');
    });

    client.on('error', function (err) {
        console.log('Something went wrong with Redis client ' + err);
    });

}).catch((err) => {
    console.error("Error connecting to redis", err);
});

let app = express();

const PORT = process.env.PORT || 5000;

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

class CustomError extends Error {
    constructor({ message, status }) {
        super(message);
        this.status = status;
    }
}

app.use(session({
    store: new RedisStore({ client: client, prefix: 'myapp:' }),
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

let oauth2_token_json = null;

app.get('/connect', function (req, res) {
    logger.info('GET /connect route hit');
    logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);

    const authUri = req.oauthClient.authorizeUri({
        scope: ['com.intuit.quickbooks.accounting'],
        state: tokens.create(req.sessionID),
    });
    logger.info('Redirecting to: ' + authUri);
    res.redirect(authUri);
});

app.get('/callback', async (req, res, next) => {
    try {
        const authResponse = await oauthClient.createToken(req.url);
        req.session.oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(req.session.oauth2_token_json);
    } catch (e) {
        logger.error("Error in /callback: ", e);
        next(new CustomError({ message: `Failed to create token: ${e.message}`, status: 500 }));
    }
});

app.get('/refreshAccessToken', async (req, res, next) => {
    try {
        const authResponse = await oauthClient.refresh();
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(oauth2_token_json);
    } catch (e) {
        logger.error("Error in /refreshAccessToken: ", e);
        next(new CustomError({ message: `Failed to refresh token: ${e.message}`, status: 500 }));
    }
});

app.get('/getCompanyInfo', async (req, res, next) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/companyinfo/${companyID}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: finalUrl });
        res.send(JSON.parse(authResponse.text()));
    } catch (e) {
        logger.error("Error in /getCompanyInfo: ", e);
        next(new CustomError({ message: `Failed to get company info: ${e.message}`, status: 500 }));
    }
});

app.get('/getGeneralLedger', [
    check('start_date').custom(value => isValid(new Date(value))),
    check('end_date').custom(value => isValid(new Date(value))),
    check('accounting_method').isIn(['Cash', 'Accrual']),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/reports/GeneralLedger`;

    const queryParams = req.query;

    const urlWithParams = `${finalUrl}?${new URLSearchParams(queryParams).toString()}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: urlWithParams });
        res.send(JSON.parse(authResponse.text()));
    } catch (e) {
        next(new CustomError({ message: `Failed to get general ledger: ${e.message}`, status: 500 }));
    }
});


app.get('/', (req, res) => {
    res.send('Welcome to Quickbookks!');
});

app.use((err, req, res, next) => {
    const status = err.status || 500;
    res.status(status);
    logger.error(`${status} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

    if (process.env.NODE_ENV === 'development') {
        res.json({
            status: status,
            message: err.message,
            stack: err.stack
        });
    } else {
        res.json({
            status: status,
            message: 'Something went wrong'
        });
    }
});

app.listen(PORT, function () {
    console.log(`Started on port ${PORT}`);
});
