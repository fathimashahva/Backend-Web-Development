'use strict';

require('dotenv').config();

const crypto = require('crypto');
const { handleEvent } = require('./eventHandlers');

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const _processedIds = new Set();

async function handleWebhook(req, res) {
  // 1. Verify HMAC-SHA256 signature
  const signature = req.headers['x-webhook-signature'];

  if (!signature || !signature.startsWith('sha256=')) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const received = signature.slice(7);

  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET|| 'testsecret')
    .update(req.body)
    .digest('hex');

  try {
    const expectedBuffer = Buffer.from(expected, 'hex');
    const receivedBuffer = Buffer.from(received, 'hex');

    if (
      expectedBuffer.length !== receivedBuffer.length ||
      !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
    ) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  } catch {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // 2. Parse body
  const event = JSON.parse(req.body);

  // 3. Idempotency check
  if (_processedIds.has(event.id)) {
    return res.status(200).json({ status: 'already_processed' });
  }

  // 4. Mark as processed
  _processedIds.add(event.id);

  // 5. Acknowledge immediately, then process asynchronously
  res.status(200).json({ status: 'received' });

  setImmediate(() => {
    handleEvent(event);
  });
}

module.exports = { handleWebhook, _processedIds };