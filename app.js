require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');
const config = require('./config.json');
const logger = require('./logger');
const csrf = require('csrf');
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
    // Ensure state parameter is present
    if (!req.query.state) {
        return next(new CustomError({ message: `Missing state parameter`, status: 400 }));
    }

    // Validate CSRF token
    if (!tokens.verify(req.sessionID, req.query.state)) {
        return next(new CustomError({ message: `Invalid CSRF token`, status: 400 }));
    }

    try {
        const authResponse = await oauthClient.createToken(req.url);
        const { access_token, refresh_token, expires_in } = authResponse.getJson();
        req.session.oauth2_token_json = { access_token, refresh_token, expires_in };
        // Set auth cookie for subsequent requests
        res.cookie('quickbooks_token', JSON.stringify(req.session.oauth2_token_json), { httpOnly: true });
        res.redirect(`https://6b0c-73-68-198-127.ngrok-free.app/callback?token=${JSON.stringify(req.session.oauth2_token_json)}`); 
    } catch (e) {
        logger.error("Error in /callback: ", e);
        next(new CustomError({ message: `Failed to create token: ${e.message}`, status: 500 }));
    }
});


app.post('/storeToken', async (req, res, next) => {
    try {
        const { access_token, refresh_token, expires_in } = req.body;

        // Validation of input data
        if(!access_token || !refresh_token || !expires_in){
            throw new Error("Missing required field(s)");
        }

        const expiryTime = parseInt(expires_in); // make sure expires_in is a number

        if(isNaN(expiryTime)){
            throw new Error("expires_in must be a number");
        }

        // Save tokens in Redis
        const access_token_res = await client.set('access_token', access_token, 'EX', expiryTime);
        const refresh_token_res = await client.set('refresh_token', refresh_token);

        // Check if the tokens were stored correctly
        if (access_token_res !== 'OK' || refresh_token_res !== 'OK') {
            throw new Error("Failed to store tokens in Redis");
        }

        res.sendStatus(200);
    } catch (e) {
        logger.error("Error in /storeToken: ", e);
        next(new CustomError({ message: `Failed to store token: ${e.message}`, status: 500 }));
    }
});

// Route for token refresh
app.get('/refreshToken', async (req, res, next) => {
    try {
        const refresh_token = await client.get('refresh_token');

        if(!refresh_token){
            throw new Error("No refresh token available");
        }

        // Call the method for refreshing tokens
        const authResponse = await oauthClient.refreshUsingToken(refresh_token);

        const { access_token, expires_in } = authResponse.getJson();

        // Save the new access token in Redis
        const access_token_res = await client.set('access_token', access_token, 'EX', expires_in);

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

    const queryParams = {
        ...req.query,
        columns: 'tx_date, txn_type, doc_num, name, memo, split_acc, subt_nat_amount, account_name, chk_print_state, create_by, create_date, cust_name, emp_name, inv_date, is_adj, is_ap_paid, is_ar_paid, is_cleared, item_name, last_mod_by, last_mod_date, quantity, rate, vend_name'
    };

    const urlWithParams = `${finalUrl}?${new URLSearchParams(queryParams).toString()}`;

    try {
        const authResponse = await oauthClient.makeApiCall({ url: urlWithParams });
        if (!authResponse || !authResponse.ok) {
            throw new CustomError({ message: `API request failed with status ${authResponse ? authResponse.status : 'unknown'}`, status: authResponse ? authResponse.status : 500 });
        }
        res.send(JSON.parse(authResponse.text()));
    } catch (e) {
        next(e instanceof CustomError ? e : new CustomError({ message: `Failed to get general ledger: ${e.message}`, status: 500 }));
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
