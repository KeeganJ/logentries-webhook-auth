const Authorizer = require('../build/authorizer').Authorizer;

describe('LogentriesWebhookAuthExpress', function() {

  describe('->getFromAuthorizationHeader', function() {

    beforeEach(function() {
      return this.makeFakeGet = request => {
        return header => request.headers[header];
      };
    });

    describe('with a valid LE token', function() {

      describe(`when the body is a string`, function () {

        beforeEach(function() {
          this.sut = new Authorizer({password: 'pre-shared-key'});
          this.next = sinon.spy();

          this.request = {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
              'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
              authorization: 'LE greenish-yellow:+x/QCSqyGmY0XmxQ5tq8qUWGGDc='
            },
            body: 'abcdeft',
            path: '/somewhere'
          };

          this.request.get = this.makeFakeGet(this.request);
          return this.sut.getFromAuthorizationHeader(this.request);
        });

        it('should set logentriesWebhookAuth on the request', function() {
          return expect(this.request.logentriesWebhookAuth).to.deep.equal({
            user: 'greenish-yellow',
            hash: '+x/QCSqyGmY0XmxQ5tq8qUWGGDc='
          });
        });

      });

      describe(`when the body is an object`, function () {

        beforeEach(function() {
          this.sut = new Authorizer({password: 'pre-shared-key'});
          this.next = sinon.spy();

          this.request = {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
              'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
              authorization: 'LE greenish-yellow:evLgXp13JNDum+WG0y0xHuqkjQ8='
            },
            body: {
              hello: {
                there: {
                  objects: "string"
                }
              }
            },
            path: '/somewhere'
          };

          this.request.get = this.makeFakeGet(this.request);
          return this.sut.getFromAuthorizationHeader(this.request);
        });

        it('should set logentriesWebhookAuth on the request', function() {
          return expect(this.request.logentriesWebhookAuth).to.deep.equal({
            user: 'greenish-yellow',
            hash: 'evLgXp13JNDum+WG0y0xHuqkjQ8='
          });
        });

      });
    });

    describe('with a different valid LE token', function() {

      beforeEach(function() {
        this.sut = new Authorizer({password: 'shared-key-pre'});
        this.next = sinon.spy();

        this.request = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
            authorization: 'LE super-pink:uHvt/OOVkCqV58aFIDaPNsHZRtg='
          },
          body: 'fobar',
          path: '/b0rked'
        };

        this.request.get = this.makeFakeGet(this.request);
        return this.sut.getFromAuthorizationHeader(this.request);
      });

      it('should set logentriesWebhookAuth on the request', function() {
        expect(this.request.logentriesWebhookAuth).to.deep.equal({
          user: 'super-pink',
          hash: 'uHvt/OOVkCqV58aFIDaPNsHZRtg='
        });
      });
    });

    describe('with a invalid LE token', function() {

      beforeEach(function() {
        this.sut = new Authorizer({password: 'shared'});
        this.next = sinon.spy();

        this.request = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
            authorization: 'LE user:zpwaW5raXNoLBAD'
          },
          body: 'totally haxxored'
        };

        this.request.get = this.makeFakeGet(this.request);
        return this.sut.getFromAuthorizationHeader(this.request);
      });

      it('should not set logentriesWebhookAuth on the request', function() {
        expect(this.request.logentriesWebhookAuth).to.not.exist;
      });
    });
  });
});
