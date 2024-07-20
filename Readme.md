# Supertokens JWT Helper

## Purpose

A small node library that makes it easy to create, verify and decode jwts. It requires the following environment variables to be set in the calling node application/code and to be set via the `EnvHandler.getInstance().setEnv(process.env)` call **BEFORE ANY CALL IS MADE VIA THE** `JWTHandler` Singleton Class:

- `NEXT_SERVER_API_DOMAIN` - The **domain name** where the Supertokens API (recipes)

- `NEXT_SERVER_API_BASE_PATH` - Base (API) path for where Supertokens (recipes) are initiated | _Looks like_ `/api/auth` (_this is usually set in your Supertokens `appConfig` file_)

- `NEXT_SERVER_SUPERTOKENS_CORE` - Url for the `supertokens-core` instance _(This depends on whether this is hosted by Supertokens or Self-Hosted [via docker])_

The user of this module should also call the setEnvs method of the EnvHandler singleton, passing in the `process.env` object from the parent node application. This allows the JWTHandler to have access to the parent environment variables.

The supertokens auth instance (the project where supertokens-node module is used along with the supertokens recipes) must also be running for this to work properly, as the module will send a request to the supertokens instance to retrieve a jwt.
