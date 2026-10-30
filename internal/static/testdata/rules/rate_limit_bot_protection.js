const express = require('express');
const rateLimit = require('express-rate-limit');

function unprotected() {
  // ruleid: sift.rate-limit-missing
  const app = express();
  app.get('/', (req, res) => res.send('ok'));
}

function protectedInline() {
  // ok: sift.rate-limit-missing
  const app = express();
  app.use(rateLimit({ windowMs: 60000, max: 100 }));
}

function protectedVariable() {
  const limiter = rateLimit({ windowMs: 60000, max: 100 });
  // ok: sift.rate-limit-missing
  const app = express();
  app.use(limiter);
}

function protectedPath() {
  // ok: sift.rate-limit-missing
  const app = express();
  const apiLimiter = rateLimit({ max: 10 });
  app.use('/api', apiLimiter);
}
