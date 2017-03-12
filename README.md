# Introduction

This service is designed to facilitate a simple set of purposes:

* Support OAuth2 authentication code and refresh token grant flows from a Google Assistant, like Google Home
* Support user authentication via Google allowing users to store their subscriber ID alongside a redirect URL that will be used to fulfill voice requests - this permits deployment of Google Actions packages where each user will have their own fulfillment service, while this service can simply authenticate and redirect, getting out of the middle

User authentication via Google Identity is the only supported mechanism.  Since the Google Assistants and Homes of the world are the only intended subjects, all users will almost certainly have a valid Google account to link their devices.  This allows us to reduce the risk of database compromise by maintaining a simpler user document without requiring the storage of hashed passwords, names, or email addresses.

# Deploying An Azure Web App

To deploy the Azure ARM template, use the NodeJS or new Python Azure CLI or Powershell to deploy the template to a resource group you've already created in your Azure subscription.

# Seed Client Data to MongoDB

Before using the application, you must connect to the database and write the OAuth2 client data.  You can use the seed-client.js script to do this.

Login to the Azure portal and find the connection string for your DocumentDB instance.  Set the environment variable MONGODB_URI to this value.

Run `node seed-client.js` to write the client information to the database.

# References

* https://developers.google.com/actions/develop/sdk/
* https://github.com/oauthjs/node-oauth2-server
* https://github.com/ubilogix/koa2-oauth-server
* https://developers.google.com/identity/sign-in/web/sign-in

