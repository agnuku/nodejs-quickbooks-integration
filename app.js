// app.js

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const OAuthClient = require('intuit-oauth');
const indexRouter = require('./routes/index');
const config = require('./config.json');  // import the config.json file

let app = express();

// Get the port from environment or use 4000 as default
const PORT = process.env.PORT || 4000;

// Define redirectUri based on the environment
const redirectUri = process.env.NODE_ENV === 'production' 
    ? 'https://your-production-app.herokuapp.com/callback'
    : 'http://localhost:4000/callback';

// Instantiate new client
let oauthClient = new OAuthClient({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    environment: 'sandbox',
    redirectUri: redirectUri,
    logging: true, // add this line
});

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
    next();
});

app.use('/', indexRouter);

app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});
