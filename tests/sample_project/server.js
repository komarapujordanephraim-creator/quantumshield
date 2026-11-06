const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const token = jwt.sign({ user: 1 }, 'secret', { algorithm: 'RS256' });
const h = crypto.createHash('sha1');
