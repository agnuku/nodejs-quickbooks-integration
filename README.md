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