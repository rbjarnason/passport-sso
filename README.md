# passport-sso
Multi-domain single signon functionality using passport

I have created  project that implements this for [Sails.js](http://sailsjs.org/).
See [sails-hook-sso](https://github.com/mattmccarty/sails-hook-sso) for more information.

### Getting started

1. ) Install PassportSSO
```npm install passport-sso```

2.) Install the passport-local package
```npm install passport-local --save```

3.) Install the passport-google-oauth package
```npm install passport-google-oauth --save```

4.) Initialize SSO with hosts that your app supports and login provider details
```javascript
function localLoginCallback(req, id, pw, cb) {
    if (id == 'admin' && pw === 'test12345') {
        return cb(false, { username: 'admin' });
    }

    return cb('Either the username or password is incorrect');
}

var sso       = require('passport-sso'),
    hosts     = ['localhost', '127.0.0.1'],
    providers = [{
        name            : 'local-strategy-1',
        provider        : 'local',
        protocol        : 'local',
        strategyObject  : 'Strategy',
        strategyPackage : 'passport-local',
        clientID        : 'false',
        clientSecret    : 'false',
        scope           : [],
        fields          : null,
        urlCallback     : 'http://localhost/user/auth/local-strategy-1/callback'
    }, {
        name            : 'google-strategy-1',
        provider        : 'google',
        protocol        : 'oauth2',
        strategyObject  : 'Strategy',
        strategyPackage : 'passport-google-oauth',
        clientID        : 'YOUR-GOOGLE-CLIENT-ID',
        clientSecret    : 'YOUR-GOOGLE-CLIENT-SECRET',
        scope           : ['email', 'profile'],
        fields          : null,
        urlCallback     : 'http://localhost/user/auth/google-strategy-1/callback'
    }];

sso.init(hosts, providers, null, localLoginCallback);
```


to be continued....
