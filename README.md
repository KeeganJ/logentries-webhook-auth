# Logentries Webhook Authentication Middleware for Express

[![CircleCI](https://circleci.com/gh/thirdiron/logentries-webhook-auth.svg?style=svg)](https://circleci.com/gh/thirdiron/logentries-webhook-auth)

Express middleware for logentries webhook api, written in typescript with types available.

[Logentries documentation on webhooks](https://docs.logentries.com/docs/webhookalert#section-authentication)

# Usage

```js
  const express = require('express');
  const bodyParser = require('body-parser');  // Optional.
  const logentriesWebhookAuth = require('logentries-webhook-auth');
  
  const app = express();

  // This step isn't necessary for authentication, but you'll want it 
  // if you want to parse the payload that LogEntries posts.
  app.use(bodyParser.urlencoded({
    extended: true
  }));

  // Use the middleware with a pre shared password.
  app.use(logentriesWebhookAuth('password'));

  // "user" is now available on request.logentriesWebhookAuth.user
  // "payload" is now available on request.body

  // ...Your routes here...

  app.listen(3000);
```

# Development

- `npm install`   - Setup dependencies and build project
- `npm run build` - Build source files manually
- `npm test`      - Run tests

## Environment Variables

`ENABLE_LOGENTRIES_WEBHOOK_AUTH_LOGGING` : Enable logging from this middleware. This will log hashes and signatures, don't enable this in production.
