require('dotenv').config();

const express = require('express');
const path = require('path');
const OAuthClient = require('intuit-oauth');
const bodyParser = require('body-parser');

const app = express();

// Get the port from environment or use 4000 as default
const PORT = process.env.PORT || 4000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '/public')));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.use(bodyParser.json())

let oauth2_token_json = null;
let oauthClient = null;

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/authUri', bodyParser.urlencoded({ extended: false }), (req, res) => {
    oauthClient = new OAuthClient({
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        environment: process.env.ENVIRONMENT,
        redirectUri: process.env.REDIRECT_URI
    });

    const authUri = oauthClient.authorizeUri({ scope: [OAuthClient.scopes.Accounting], state: 'intuit-test' });
    res.send(authUri);
});

app.get('/callback', async (req, res) => {
    try {
        const authResponse = await oauthClient.createToken(req.url);
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(oauth2_token_json);
    } catch(e) {
        console.error(e);
        res.status(500).send('Failed to create token');
    }
});

app.get('/retrieveToken', (req, res) => {
    res.send(oauth2_token_json);
});

app.get('/refreshAccessToken', async (req, res) => {
    try {
        const authResponse = await oauthClient.refresh();
        oauth2_token_json = JSON.stringify(authResponse.getJson(), null, 2);
        res.send(oauth2_token_json);
    } catch(e) {
        console.error(e);
        res.status(500).send('Failed to refresh token');
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
        console.error(e);
        res.status(500).send('Failed to get company info');
    }
});

app.listen(PORT, function(){
    console.log(`Started on port ${PORT}`);
});

