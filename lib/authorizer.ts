import * as crypto from 'crypto';
import { ExpressRequest, AuthData } from './interfaces';

const debugLog = process.env.ENABLE_LOGENTRIES_WEBHOOK_AUTH_LOGGING
  ? console.log
  : (message) => {};

export class Authorizer {
  password: string;

  constructor(password: string) {
    if (!password) throw new Error(`'password' is required for logentries webhook auth.`);
    this.password = password;
  }

  getAuthData(request: ExpressRequest): AuthData {
    if (request.headers == null) return null;

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
      return null;
    }

    const [user, hash] = parts[1].split(':');

    if (!this._checkHash(request, hash)) { return null; }

    const authData: AuthData = {
      user: user.trim(),
      hash
    };

    debugLog(authData);
    return authData;
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
