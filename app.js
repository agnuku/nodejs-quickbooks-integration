require('dotenv').config();
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;  // Import the connect-redis library
const redis = require('redis');  // Import the redis library
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');  
const logger = require('./logger');
const csrf = require('csrf');
const tokens = new csrf(); 
const { check, validationResult } = require('express-validator');

let client;

client = redis.createClient({
    password: 'JME1T2W9hOj7A2vwzuAzLSeh2AgM5lAa',
    socket: {
        host: 'redis-17187.c92.us-east-1-3.ec2.cloud.redislabs.com',
        port: 17187
    }
});

client.on('connect', function() {
    console.log('Redis client connected');
});

client.on('ready', function() {
    console.log('Redis client is ready');
});

client.on('reconnecting', function() {
    console.log('Redis client reconnecting');
});

client.on('end', function() {
    console.log('Redis client connection ended');
});

client.on('error', function (err) {
    console.log('Something went wrong with Redis client ' + err);
});

client.on('error', function (err) {
    console.log('Something went wrong ' + err);
});

let app = express();

// Get the port from environment or use 4000 as default
const PORT = process.env.PORT || 5000;

logger.debug('process.env.NODE_ENV: ' + process.env.NODE_ENV);
logger.debug('process.env.PORT: ' + process.env.PORT);

// Define redirectUri based on the environment
const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.debug('redirectUri: ' + redirectUri);

// Instantiate new client
let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});

// Log only key properties of the oauthClient
logger.info("OAuth Client created with clientId: " + oauthClient.clientId + ", environment: " + oauthClient.environment);

//This custom class will allow us to throw specific errors with context
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

// Set oauthClient in middleware so we can access it in routes
app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object with clientId: " + req.oauthClient.clientId);
    next();
});

let oauth2_token_json = null; // Add this line

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

app.get('/callback', async (req, res) => {
    try {
        const authResponse = await oauthClient.createToken(req.url);
        req.session.oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2); // Store in session
        res.send(req.session.oauth2_token_json);
    } catch(e) {
        logger.error("Error in /callback: ", e);
        res.status(500).json({
            success: false,
            message: `Failed to create token: ${e.message}`,
            stack: process.env.NODE_ENV === 'development' ? e.stack : undefined,
        });
    }
});


app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await oauthClient.refresh();
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(oauth2_token_json);
    } catch(e) {
        console.error("Error in /refreshAccessToken: ", e);
        res.status(500).send(`Failed to refresh token: ${e.message}`);
    }
});

app.get('/getCompanyInfo', async (req, res) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/companyinfo/${companyID}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: finalUrl });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        console.error("Error in /getCompanyInfo: ", e);
        res.status(500).send(`Failed to get company info: ${e.message}`);
    }
});

app.get('/getGeneralLedger', [
    check('start_date').isDate(),
    check('end_date').isDate(),
    check('accounting_method').isIn(['Cash', 'Accrual']),
    // Add more validations as needed...
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;
    const finalUrl = `${url}v3/company/${companyID}/reports/GeneralLedger`;

    // Use the query parameters from the request
    const queryParams = req.query;

    const urlWithParams = `${finalUrl}?${new URLSearchParams(queryParams).toString()}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: urlWithParams });
        res.send(JSON.parse(authResponse.text()));
    } catch(e) {
        next(new CustomError({ message: `Failed to get general ledger: ${e.message}`, status: 500 }));
    }
});

//Root route
app.get('/', (req, res) => {
    res.send('Welcome to Quickbookks!');
});

// Add error handling middleware
app.use((err, req, res, next) => {
    logger.error(err.message);
    if (process.env.NODE_ENV !== 'production') {
        logger.error(err.stack);
    }

    res.status(err.status || 500).send({
        error: {
            message: err.message,
            status: err.status,
        }
    });
});

app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});