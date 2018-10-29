import * as crypto from 'crypto';
import { AuthorizerOptions, ExpressRequest } from './interfaces';
import { inspect } from 'util';

const debugLog = process.env.ENABLE_LOGENTRIES_WEBHOOK_AUTH_LOGGING
  ? console.log
  : (message) => {};

export class Authorizer {
  options: AuthorizerOptions;

  constructor(options: AuthorizerOptions, dependencies?: any) {
    this.getFromAuthorizationHeader = this.getFromAuthorizationHeader.bind(this);
    this._checkHash = this._checkHash.bind(this);
    if (options == null) { options = {}; }
    this.options = options;
    if (dependencies == null) { dependencies = {}; }
    if (this.options.bodyParam == null) { this.options.bodyParam = 'body'; }
  }

  getFromAuthorizationHeader(request: ExpressRequest) {
    if (request.headers == null) return;

    debugLog('Authorization', request.headers.authorization);
    const parts = request.headers.authorization !== null
      ? request.headers.authorization.split(' ')
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
    const body = request[this.options.bodyParam] !== null
      ? request[this.options.bodyParam].toString()
      : undefined;

    debugLog('body', inspect(body));

    const bodyHash = crypto.createHash('md5');
    bodyHash.update(body);
    const content_md5 = bodyHash.digest('base64');
    debugLog('content_md5', content_md5);

    const canonical = [
      'POST',
      request.get('Content-Type'),
      content_md5,
      request.get('Date'),
      request.path,
      request.get('X-Le-Nonce')
    ].join("\n");

    debugLog('canonical', canonical);

    const hmac = crypto.createHmac('sha1', this.options.password);
    hmac.update(canonical)
    const signature = hmac.digest('base64');
    debugLog('signature', signature, hash);

    debugLog('signature === hash', signature === hash);
    return signature === hash;
  }
}
