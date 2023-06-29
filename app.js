const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const OAuthClient = require('intuit-oauth');
const indexRouter = require('./routes/index');
const config = require('./config.json');  // import the config.json file
const logger = require('./logger');

let app = express();

// Get the port from environment or use 4000 as default
const PORT = process.env.PORT || 4000;

// Define redirectUri based on the environment
const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://quickbookks-f425c88c6f16.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

logger.debug('redirectUri: ', redirectUri);

// Instantiate new client
let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true,
});
logger.info("OAuth Client created: ", oauthClient);
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set oauthClient in middleware so we can access it in routes
app.use((req, res, next) => {
    req.oauthClient = oauthClient;
    logger.debug("OAuthClient added to request object: ", req.oauthClient);
    next();
});

app.use('/', indexRouter);

app.listen(PORT, function(){
    logger.info(`Started on port ${PORT}`);
});
