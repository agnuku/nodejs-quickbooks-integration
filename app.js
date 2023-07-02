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
const cookieParser = require('cookie-parser');

let client;

client = redis.createClient({
    password: 'JME1T2W9hOj7A2vwzuAzLSeh2AgM5lAa',
    socket: {
        host: 'redis-17187.c92.us-east-1-3.ec2.cloud.redislabs.com',
        port: 17187
    }
});

client.connect().then(() => {
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
app.use(cors({
    origin: 'https://6b0c-73-68-198-127.ngrok-free.app', // or your frontend origin
    credentials: true
}));


const PORT = process.env.PORT || 5000;

logger.debug('process.env.NODE_ENV: ' + process.env.NODE_ENV);
logger.debug('process.env.PORT: ' + process.env.PORT);

// Use morgan for request logging and make it use the winston logger
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

app.use(cookieParser());

app.get('/callback', async (req, res, next) => {
    if (!req.query.state) {
        return next(new CustomError({ message: `Missing state parameter`, status: 400 }));
    }
    if (!tokens.verify(req.sessionID, req.query.state)) {
        return next(new CustomError({ message: `Invalid CSRF token`, status: 400 }));
    }
    try {
        const authResponse = await oauthClient.createToken(req.url).catch(e => { throw e; });
        const { access_token, refresh_token, expires_in } = authResponse.getJson();
        req.session.oauth2_token_json = { access_token, refresh_token, expires_in };
        res.cookie('quickbooks_token', JSON.stringify(req.session.oauth2_token_json), { httpOnly: true, sameSite: 'none', secure: true });
        res.redirect(`https://6b0c-73-68-198-127.ngrok-free.app/callback?token=${JSON.stringify(req.session.oauth2_token_json)}`); 
    } catch (e) {
        logger.error("Error in /callback: ", e);
        next(new CustomError({ message: `Failed to create token: ${e.message}`, status: 500 }));
    }
});

app.post('/storeToken', async (req, res, next) => {
    try {
        const { access_token, refresh_token, expires_in } = req.body;
        if(!access_token || !refresh_token || !expires_in){
            throw new Error("Missing required field(s)");
        }
        const expiryTime = parseInt(expires_in);
        if(isNaN(expiryTime)){
            throw new Error("expires_in must be a number");
        }
        const access_token_res = await client.set('access_token', access_token, 'EX', expiryTime).catch(e => { throw e; });
        const refresh_token_res = await client.set('refresh_token', refresh_token).catch(e => { throw e; });
        if (access_token_res !== 'OK' || refresh_token_res !== 'OK') {
            throw new Error("Failed to store tokens in Redis");
        }
        res.sendStatus(200);
    } catch (e) {
        logger.error("Error in /storeToken: ", e);
        next(new CustomError({ message: `Failed to store token: ${e.message}`, status: 500 }));
    }
});

app.get('/refreshToken', async (req, res, next) => {
    try {
        const refresh_token = await client.get('refresh_token').catch(e => { throw e; });
        if(!refresh_token){
            throw new Error("No refresh token available");
        }
        const authResponse = await oauthClient.refreshUsingToken(refresh_token).catch(e => { throw e; });
        const { access_token, expires_in } = authResponse.getJson();
        const access_token_res = await client.set('access_token', access_token, 'EX', expires_in).catch(e => { throw e; });
        if (access_token_res !== 'OK') {
            throw new Error("Failed to store new access token in Redis");
        }
        res.sendStatus(200);
    } catch (e) {
        logger.error("Error in /refreshToken: ", e);
        next(new CustomError({ message: `Failed to refresh token: ${e.message}`, status: 500 }));
    }
});

app.get('/getCompanyInfo', async (req, res, next) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = url.replace('https://', 'https://quickbooks.api.intuit.com/') + `v3/company/${companyID}/companyinfo/${companyID}`;
    try {
        const authResponse = await oauthClient.makeApiCall({ url: finalUrl }).catch(e => { throw e; });
        res.send(JSON.parse(authResponse.text()));
    } catch (e) {
        logger.error("Error in /getCompanyInfo: ", e);
        next(new CustomError({ message: `Failed to fetch company info: ${e.message}`, status: 500 }));
    }
});

app.get('/getGeneralLedger', [
    check('start_date').isISO8601().withMessage('start_date must be a valid date in YYYY-MM-DD format'),
    check('end_date').isISO8601().withMessage('end_date must be a valid date in YYYY-MM-DD format'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return next(new CustomError({ message: errors.array(), status: 400 }));
    }
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const urlWithParams = url.replace('https://', 'https://quickbooks.api.intuit.com/') + `v3/company/${companyID}/reports/GeneralLedger?start_date=${req.query.start_date}&end_date=${req.query.end_date}`;
    try {
        const authResponse = await oauthClient.makeApiCall({ url: urlWithParams }).catch(e => { throw e; });
        res.send(JSON.parse(authResponse.text()));
    } catch (e) {
        logger.error("Error in /getGeneralLedger: ", e);
        next(new CustomError({ message: `Failed to fetch General Ledger: ${e.message}`, status: 500 }));
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
    logger.info(`Started on port ${PORT}`);
});
