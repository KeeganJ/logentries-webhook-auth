LogentriesWebhookAuthExpress = require '../src/logentries-webhook-auth-express'

describe 'LogentriesWebhookAuthExpress', ->
  describe '->getFromAuthorizationHeader', ->
    beforeEach ->
      @makeFakeGet = (request) =>
        return (header) => request.headers[header]

    describe 'with a valid LE token', ->
      beforeEach ->
        @sut = new LogentriesWebhookAuthExpress password: 'pre-shared-key'
        @next = sinon.spy()
        @request =
          headers:
            'Content-Type': 'application/x-www-form-urlencoded'
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT'
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG'
            authorization: 'LE greenish-yellow:+x/QCSqyGmY0XmxQ5tq8qUWGGDc='
          body: 'abcdeft'
          path: '/somewhere'

        @request.get = @makeFakeGet @request
        @sut.getFromAuthorizationHeader(@request)

      it 'should set logentriesWebhookAuth on the request', ->
        expect(@request.logentriesWebhookAuth).to.deep.equal user: 'greenish-yellow', hash: '+x/QCSqyGmY0XmxQ5tq8qUWGGDc='

    describe 'with a different valid LE token', ->
      beforeEach ->
        @sut = new LogentriesWebhookAuthExpress password: 'shared-key-pre'
        @next = sinon.spy()
        @request =
          headers:
            'Content-Type': 'application/x-www-form-urlencoded'
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT'
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG'
            authorization: 'LE super-pink:uHvt/OOVkCqV58aFIDaPNsHZRtg='
          body: 'fobar'
          path: '/b0rked'

        @request.get = @makeFakeGet @request
        @sut.getFromAuthorizationHeader(@request)

      it 'should set logentriesWebhookAuth on the request', ->
        expect(@request.logentriesWebhookAuth).to.deep.equal user: 'super-pink', hash: 'uHvt/OOVkCqV58aFIDaPNsHZRtg='

    describe 'with a invalid LE token', ->
      beforeEach ->
        @sut = new LogentriesWebhookAuthExpress password: 'shared'
        @next = sinon.spy()
        @request =
          headers:
            'Content-Type': 'application/x-www-form-urlencoded'
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT'
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG'
            authorization: 'LE user:zpwaW5raXNoLBAD'
          body: 'totally haxxored'

        @request.get = @makeFakeGet @request
        @sut.getFromAuthorizationHeader(@request)

      it 'should set logentriesWebhookAuth on the request', ->
        expect(@request.logentriesWebhookAuth).to.not.exist
