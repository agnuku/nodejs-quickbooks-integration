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
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = `The CORS policy for this site does not allow access from the specified origin.`;
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
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
    cookie: { secure: false }  // For development purposes, use secure: true for production environments
}));

// Debugging middleware
app.use((req, res, next) => {
    console.log(req.session);
    next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object with clientId: " + req.oauthClient.clientId);
    next();
});

let oauth2_token_json = null;

app.use(cookieParser());

// Middlewares

// Middleware to check token and refresh if necessary
app.use(async (req, res, next) => {
    const { oauth2_token_json } = req.session;

    if (!oauth2_token_json) {
        return next();
    }

    const { access_token, refresh_token, expires_at } = oauth2_token_json;

    // If token has expired, refresh it
    if (Date.now() >= expires_at) {
        try {
            const authResponse = await oauthClient.refreshUsingToken(refresh_token);
            const { access_token, refresh_token, expiresIn } = authResponse.getJson();

            // Add the new token and expiry time to the session
            req.session.oauth2_token_json = {
                access_token,
                refresh_token,
                expires_at: Date.now() + expiresIn * 1000
            };
        } catch (e) {
            logger.error("Error in token refresh middleware: ", e);
            return next(new CustomError({ message: `Failed to refresh token: ${e.message}`, status: 500 }));
        }
    }

    next();
});
app.use(cookieParser());


app.get('/connect', async (req, res, next) => {
    try {
        logger.info('GET /connect route hit');
        logger.debug("In /connect route, req.oauthClient clientId: " + req.oauthClient.clientId);
    
        const authUri = req.oauthClient.authorizeUri({
            scope: ['com.intuit.quickbooks.accounting'],
            state: tokens.create(req.sessionID),
        });
        logger.info('Redirecting to: ' + authUri);
        res.redirect(authUri);
    } catch (e) {
        logger.error("Error in /connect: ", e);
        next(new CustomError({ message: `Failed to redirect to authUri: ${e.message}`, status: 500 }));
    }
});

app.get('/callback', async (req, res, next) => {
    if (!req.query.state) {
        return next(new CustomError({ message: `Missing state parameter`, status: 400 }));
    }
    if (!tokens.verify(req.sessionID, req.query.state)) {
        return next(new CustomError({ message: `Invalid CSRF token`, status: 400 }));
    }
    try {
        const authResponse = await oauthClient.createToken(req.url).catch(e => { throw e; });
        logger.debug("authResponse: " + JSON.stringify(authResponse));
        const { access_token, refresh_token, expires_in } = authResponse.getJson();
        logger.debug("access_token: " + access_token);
        logger.debug("refresh_token: " + refresh_token);
        logger.debug("expires_in: " + expires_in);

        // Log the creation and expiry date/time of the token
        const created_at = Date.now();
        const expires_at = created_at + expires_in * 1000;
        logger.debug("Token created at: " + new Date(created_at).toISOString());
        logger.debug("Token expires at: " + new Date(expires_at).toISOString());

        req.session.oauth2_token_json = { access_token, refresh_token, expires_in, created_at, expires_at };
        res.redirect(`https://6b0c-73-68-198-127.ngrok-free.app/callback?token=${JSON.stringify(req.session.oauth2_token_json)}`); 
    } catch (e) {
        logger.error("Error in /callback: ", e);
        next(new CustomError({ message: `Failed to create token: ${e.message}`, status: 500 }));
    }
});


app.get('/refreshToken', async (req, res, next) => {
    try {
        if (!req.session || !req.session.oauth2_token_json || !req.session.oauth2_token_json.refresh_token) {
            throw new Error("No refresh token available");
        }

        const authResponse = await oauthClient.refreshUsingToken(req.session.oauth2_token_json.refresh_token).catch(e => { throw e; });
        const { access_token, expires_in } = authResponse.getJson();

        req.session.oauth2_token_json.access_token = access_token;
        req.session.oauth2_token_json.expires_in = expires_in;
        req.session.oauth2_token_json.created_at = Date.now();
        req.session.oauth2_token_json.expires_at = Date.now() + expires_in * 1000;
        req.session.oauth2_token_json.realmId = oauthClient.getToken().realmId; // store company ID

        res.sendStatus(200);
    } catch (e) {
        logger.error("Error in /refreshToken: ", e);
        next(new CustomError({ message: `Failed to refresh token: ${e.message}`, status: 500 }));
    }
});

app.get('/getCompanyInfo', async (req, res, next) => {
    const companyID = oauthClient.getToken().realmId;
    const url = oauthClient.environment == 'sandbox' ? OAuthClient.environment.sandbox : OAuthClient.environment.production;

    // Retrieve the access token from the cookie
    const cookie = req.cookies.quickbooks_token;
    const tokenObj = JSON.parse(cookie);

    try {
        logger.debug("Token Object Received: " + JSON.stringify(tokenObj));

        // Validate the token object
        if (!tokenObj || !tokenObj.access_token || !tokenObj.expires_in || !tokenObj.issued_at) {
            throw new Error("Invalid token object");
        }

        // Check if the token has expired
        const currentTime = Math.floor(Date.now() / 1000);  // current time in seconds since the Unix Epoch
        if (currentTime >= tokenObj.issued_at + tokenObj.expires_in) {
            // The token has expired, refresh it
            const refreshResponse = await axios.get('/refreshToken');

            if (refreshResponse.status !== 200) {
                throw new Error("Failed to refresh the token");
            }

            // Retrieve the new token from the cookie
            const newCookie = req.cookies.quickbooks_token;
            const newTokenObj = JSON.parse(newCookie);

            if (!newTokenObj || !newTokenObj.access_token) {
                throw new Error("Failed to get the new token after refreshing");
            }

            tokenObj.access_token = newTokenObj.access_token;
        }

        // Set the token in the OAuth client
        oauthClient.setToken({ access_token: tokenObj.access_token });

        // Make the API call
        const companyInfo = await oauthClient.makeApiCall({ url: `${url}v3/company/${companyID}/companyinfo/${companyID}` });

        logger.debug("Company Info Retrieved: " + JSON.stringify(companyInfo.json));

        res.json(companyInfo.json);
    } catch (e) {
        logger.error("Error in /getCompanyInfo: ", e);

        if (e.message === 'Invalid token object' || e.message === 'The access token expired' ||
            e.message === 'Failed to refresh the token' || e.message === 'Failed to get the new token after refreshing') {
            res.status(401).json({ message: 'Unauthorized: ' + e.message });
        } else {
            logger.error("Detailed Error in /getCompanyInfo: ", e);

            next(new CustomError({ message: `Failed to get company info: ${e.message}`, status: 500 }));
        }
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

    if (!req.session || !req.session.oauth2_token_json || !req.session.oauth2_token_json.access_token) {
        return next(new CustomError({ message: 'No access token available', status: 401 }));
    }

    // Retrieve the access token from the session
    const { access_token } = req.session.oauth2_token_json;

    // Set the token to the OAuth client
    oauthClient.setToken({ access_token });

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


app.use((err, req, res, next) => {
    if (err instanceof CustomError) {
        return res.status(err.status).send(err.message);
    }
    res.status(500).send('Internal Server Error');
});

app.listen(PORT, () => {
    logger.info(`Server running on port: ${PORT}`);
});

module.exports = app;
