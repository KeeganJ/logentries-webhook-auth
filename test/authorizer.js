const Authorizer = require('../build/authorizer').Authorizer;

describe('LogentriesWebhookAuthExpress', function() {

  describe('->getAuthData', function() {

    beforeEach(function() {
      return this.makeFakeGet = request => {
        return header => request.headers[header];
      };
    });

    describe('with a valid LE token', function() {

      let response;

      beforeEach(function() {
        this.sut = new Authorizer('pre-shared-key');
        this.next = sinon.spy();

        this.request = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
            'Authorization': 'LE greenish-yellow:ss+KTRKKG2PwvWl89ceopxhEzSc=',
            'Content-Md5': 'A4O7taYfMqO/3vugWHFriA=='
          },
          originalUrl: '/somewhere'
        };

        this.request.get = this.makeFakeGet(this.request);
        response = this.sut.getAuthData(this.request);
      });

      it('should set logentriesWebhookAuth on the request', function() {
        return expect(response).to.deep.equal({
          user: 'greenish-yellow',
          hash: 'ss+KTRKKG2PwvWl89ceopxhEzSc='
        });
      });
    });

    describe('with a different valid LE token', function() {

      let response;

      beforeEach(function() {
        this.sut = new Authorizer('shared-key-pre');
        this.next = sinon.spy();

        this.request = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
            'Authorization': 'LE super-pink:J0Kxo+zCk9uvqrouBMY45gRkiO4=',
            'Content-Md5': 'A4O7taYfMqO/3vugWHFriA=='
          },
          originalUrl: '/b0rked'
        };

        this.request.get = this.makeFakeGet(this.request);
        response = this.sut.getAuthData(this.request);
      });

      it('should set logentriesWebhookAuth on the request', function() {
        expect(response).to.deep.equal({
          user: 'super-pink',
          hash: 'J0Kxo+zCk9uvqrouBMY45gRkiO4='
        });
      });
    });

    describe('with a invalid LE token', function() {

      let response;

      beforeEach(function() {
        this.sut = new Authorizer('shared');
        this.next = sinon.spy();

        this.request = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT',
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG',
            'Authorization': 'LE user:zpwaW5raXNoLBAD',
            'Content-Md5': 'A4O7taYfMqO/3vugWHFriA=='
          },
          originalUrl: '/supersecretpasswords'
        };

        this.request.get = this.makeFakeGet(this.request);
        response = this.sut.getAuthData(this.request);
      });

      it('should set logentriesWebhookAuth on the request', function() {
        expect(response).to.not.exist;
      });
    });
  });
});
