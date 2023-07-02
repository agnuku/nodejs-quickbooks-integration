require('dotenv').config();
const express = require('express');
const cors = require('cors');
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
const cookieParser = require('cookie-parser'); // Add this line

let client;

client = redis.createClient({
    password: 'JME1T2W9hOj7A2vwzuAzLSeh2AgM5lAa',
    socket: {
        host: 'redis-17187.c92.us-east-1-3.ec2.cloud.redislabs.com',
        port: 17187
    }
});

client.connect().then(() => {
    logger.info('Redis client connected');
    client.on('connect', function () {
        logger.info('Redis client connected');
    });

    client.on('ready', function () {
        logger.info('Redis client is ready');
    });

    client.on('reconnecting', function () {
        logger.info('Redis client reconnecting');
    });

    client.on('end', function () {
        logger.info('Redis client connection ended');
    });

    client.on('error', function (err) {
        logger.error('Something went wrong with Redis client ' + err);
    });

}).catch((err) => {
    logger.error("Error connecting to redis", err);
});

let app = express();
app.use(cors());
app.use(cookieParser()); // Add this line

const PORT = process.env.PORT || 5000;

logger.debug('process.env.NODE_ENV: ' + process.env.NODE_ENV);
logger.debug('process.env.PORT: ' + process.env.PORT);

app.use(logger.morgan('combined', { stream: logger.stream }));

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
        state: 'testState',
    });

    res.redirect(authUri);
});

app.get('/callback', async (req, res, next) => {
    logger.info('GET /callback route hit');
    logger.debug("In /callback route, req.oauthClient clientId: " + req.oauthClient.clientId);

    try {
        const authResponse = await oauthClient.createToken(req.url);
        const { access_token, refresh_token, expires_in } = authResponse.getJson();
        req.session.oauth2_token_json = { access_token, refresh_token, expires_in };

        // Set cookie
        res.cookie('token', JSON.stringify(req.session.oauth2_token_json), {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            sameSite: 'Strict',
            maxAge: expires_in * 1000,
        });

        res.redirect(`https://6b0c-73-68-198-127.ngrok-free.app/callback?token=${JSON.stringify(req.session.oauth2_token_json)}`);

    } catch (e) {
        logger.error("Error in /callback: ", e);
        next(new CustomError({ message: `Failed to create token: ${e.message}`, status: 500 }));
    }
});

app.listen(PORT, function () {
    logger.info(`Server started on port ${PORT}`);
});
