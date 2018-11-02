import * as crypto from 'crypto';
import { ExpressRequest } from './interfaces';

const debugLog = process.env.ENABLE_LOGENTRIES_WEBHOOK_AUTH_LOGGING
  ? console.log
  : (message) => {};

export class Authorizer {
  password: string;

  constructor(password: string, dependencies?: any) {
    this.getFromAuthorizationHeader = this.getFromAuthorizationHeader.bind(this);
    this._checkHash = this._checkHash.bind(this);

    if (!password) throw new Error(`'password' is required for logentries webhook auth.`);
    this.password = password;

    if (dependencies == null) { dependencies = {}; }
  }

  getFromAuthorizationHeader(request: ExpressRequest) {
    if (request.headers == null) return;

    const auth = request.get('Authorization');
    debugLog('Authorization header', auth);
    const parts = auth !== null
      ? auth.split(' ')
      : undefined;

    if (
      (parts == null)
      || (
        (parts[0] !== null
          ? parts[0].toLocaleUpperCase()
          : undefined
        ) !== 'LE')
    ) {
      return;
    }

    const [user, hash] = parts[1].split(':');

    if (!this._checkHash(request, hash)) { return; }

    if (request.logentriesWebhookAuth == null) {
       request.logentriesWebhookAuth = {};
    }

    request.logentriesWebhookAuth.user = user.trim();
    return request.logentriesWebhookAuth.hash = hash;
  }

  _checkHash(request: ExpressRequest, hash: string) {
    const canonical = [
      'POST',
      request.get('Content-Type'),
      request.get('Content-Md5'),
      request.get('Date'),
      request.originalUrl,
      request.get('X-Le-Nonce')
    ].join("\n");

    debugLog('canonical', canonical);

    const hmac = crypto.createHmac('sha1', this.password);
    hmac.update(canonical)
    const signature = hmac.digest('base64');

    debugLog('signature', signature);
    debugLog('hash', hash);
    debugLog('signature === hash', signature === hash);

    return signature === hash;
  }
}
