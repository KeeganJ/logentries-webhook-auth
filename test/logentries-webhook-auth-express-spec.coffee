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
            authorization: 'LE greenish-yellow:f/5LqZYHUhtLFSARTBpj8ABEpPY='
          body: 'abcdeft'
          path: '/somewhere'

        @request.get = @makeFakeGet @request
        @sut.getFromAuthorizationHeader(@request)

      it 'should set logentriesWebhookAuth on the request', ->
        expect(@request.logentriesWebhookAuth).to.deep.equal user: 'greenish-yellow', hash: 'f/5LqZYHUhtLFSARTBpj8ABEpPY='

    describe 'with a different valid LE token', ->
      beforeEach ->
        @sut = new LogentriesWebhookAuthExpress password: 'shared-key-pre'
        @next = sinon.spy()
        @request =
          headers:
            'Content-Type': 'application/x-www-form-urlencoded'
            'Date': 'Tue, 18 Aug 2015 18:14:29 GMT'
            'X-Le-Nonce': 'kzaWhO5P5yHYkUZRhbTDNEkG'
            authorization: 'LE super-pink:85R13IRcPPcU6Zkx59IHyjiSQU4='
          body: 'fobar'
          path: '/b0rked'

        @request.get = @makeFakeGet @request
        @sut.getFromAuthorizationHeader(@request)

      it 'should set logentriesWebhookAuth on the request', ->
        expect(@request.logentriesWebhookAuth).to.deep.equal user: 'super-pink', hash: '85R13IRcPPcU6Zkx59IHyjiSQU4='

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
