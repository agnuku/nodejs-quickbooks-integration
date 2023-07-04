QuickBooks Node.js OAuth2 Integration App
Oauth Concept
Before beginning, it may be helpful to have a basic understanding of OAuth 2.0 concepts. There are plenty of tutorials and guides to get started with OAuth 2.0.

It is also expected that your development environment is properly set up for Node.js and NPM.

Setup
Clone the repository:

bash
Copy code
git clone <your-repository-url>
Install NPM dependencies:

bash
Copy code
cd project directory
npm install
Launch your app:

Copy code
node app.js
Your app should be running! If you direct your browser to http://localhost:4000, you should see the welcome screen. Please note - the app will not be fully functional until we finish configuring it.

Basic Setup
markdown
Copy code
Installation Instructions:

1. Clone the app from GitHub.
2. Install the necessary NPM packages by running `npm install`.
3. Update the `config.json` file with your QuickBooks app's Client ID, Client Secret, and Redirect URI.
4. Run `node app.js` to start the application.
5. Visit your browser at http://localhost:4000.
6. Click on 'Connect to QuickBooks' to authenticate and authorize the application.
7. After successful authentication and authorization, you'll be redirected to the home page.

Configuring your app
All configuration for this app is located in config.json. We will need to update 3 items:

clientId
clientSecret
redirectUri
All of these values must match exactly with what is listed in your app settings on developer.intuit.com. If you haven't already created an app, you may do so there.

Client Credentials
Once you have created an app on Intuit's Developer Portal, you can find your credentials (Client ID and Client Secret) under the "Keys" section. These are the values you'll have to copy into config.json.

Redirect URI
You'll have to set a Redirect URI in both config.json and the Developer Portal ("Keys" section). With this app, the typical value would be http://localhost:4000/callback, unless you host this sample app in a different way.

Run your app!
After setting up both Developer Portal and your config.json, try launching your app again!

Copy code
node app.js
After successful connection with QuickBooks, you will be redirected back to the home page.

Callback URL
routes/index.js contains the callback route (/callback) that receives the authorization code, makes the bearer token exchange, and stores the access and refresh tokens in session. It then redirects to the home page.

This QuickBooks Node.js OAuth2 Integration App is a simple application to demonstrate the OAuth2 flow with Intuit's QuickBooks API. It does not include any specific QuickBooks API calls beyond authentication and authorization. For more advanced usage, refer to Intuit's API documentation and examples.


General Ledger query
Using parameters
/getGeneralLedger?start_date=2023-07-01&end_date=2023-12-31&accounting_method=Accrual



---------------------cookies-------------

Here's a summary of how the server handles cookies:

When a client initiates the OAuth process by calling /connect, the server redirects the client to the QuickBooks authentication page. An anti-CSRF token is also generated and stored in the session.

Once the user has authorized the application on the QuickBooks authentication page, they are redirected back to the /callback route on your server.

In the /callback route, the server exchanges the authorization code it received for an access token and a refresh token. These are stored in the session and set in a secure, HTTP-only cookie (quickbooks_token).

This is done with the following line of code:

javascript
Copy code
res.cookie('quickbooks_token', JSON.stringify(req.session.oauth2_token_json), { httpOnly: true, sameSite: 'none', secure: true });
This cookie is HTTP-only, which means it can't be accessed by JavaScript running in the browser. This is a security feature that helps to prevent the token from being stolen via cross-site scripting (XSS) attacks.

The SameSite attribute is set to None and the Secure attribute is set to true, which means this cookie can be sent over cross-site requests, but only over secure (HTTPS) connections.

Then, the server redirects the client back to the client-side app, including the token in the URL. The client-side app should then store this token in a cookie, which it uses for future requests to the /getCompanyInfo endpoint.

When the server receives a request to the /getCompanyInfo endpoint, it expects the token to be included in the Authorization header:

javascript
Copy code
const authHeader = req.headers.authorization;
const accessToken = authHeader && authHeader.split(' ')[1];
The one thing that should be noted is that while you are setting the token in a cookie on the server-side, the server actually expects the token to be included in the Authorization header in the /getCompanyInfo route. So on the client-side, you will need to retrieve the token from the cookie and include it in the Authorization header when making requests to the /getCompanyInfo route.

As long as your client-side code is correctly setting the token in a cookie and then including it in the Authorization header when making requests to /getCompanyInfo, this setup should work as expected.