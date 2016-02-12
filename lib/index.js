(function() {
    "use strict";

    /**
     * PassportSSO namespace.
     * @type {Object}
     */
    var PassportSSO = {};

    /**
     * Passport NPM package
     * @type {Object}
     */
    var Passport = require('passport');

    /**
     * Passport providers and their configurations
     * @type {Object}
     */
    var Strategies = {};

    /**
     * Initialize PassportSSO with the strategy config
     * @param  {Object} config - Strategy configuration object for all available providers
     * @return void
     */
    PassportSSO.init = function(config, authorize, login) {
        Passport.protocols = require('./protocols');

        for (var i = 0; i < providers.length; i++) {
            var providerOpts = providers[i],
                strategy     = null;

            if (!config[providerOpts.provider] || !config[providerOpts.provider].strategy) {
                continue;
            }

            providerOpts.passReqToCallback  = true;
            providerOpts.callbackURL        = providerOpts.urlRedirect;
            providerOpts.returnURL          = providerOpts.urlRedirect;
            providerOpts.profileFields      = providerOpts.fields || null;
            strategy                        = config[providerOpts.provider].strategy;

            switch (providerOpts.provider) {
                case 'bearer':
                    if (providerOpts.authorize) {
                        Strategies[providerOpts.name] = providerOpts;
                        Passport.use(providerOpts.name, new strategy(providerOpts.authorize));
                    }
                    continue;
                case 'local':
                    if (typeof providerOpts.login === 'function') {
                        Strategies[providerOpts.name] = providerOpts;
                        providerOpts.usernameField    = 'identifier';
                        Passport.use(providerOpts.name, new strategy(providerOpts, providerOpts.login));
                    }
                    continue;
                default:
                   Strategies[providerOpts.name] = providerOpts;
                   if (providerOpts.protocol === 'openid') {
                        providerOpts.realm   = baseUrl;
                        providerOpts.profile = true;
                    }

                    Passport.use(
                        providerOpts.name,
                        new strategy(providerOpts, Passport.protocols[providerOpts.protocol])
                    );
                    break;
            }
        };
    };

    /**
     * Redirect the user to a strategy's (i.e: google) login page
     * @param {String} strategy - The strategy name. This would have been specified
     *                            in the strategy's configuration that was passed to
     *                            PassportSSO.init()
     * @param  {Object} req - The request object
     * @param  {Object} res - The response object
     * @return void
     */
    PassportSSO.redirect = function(strategy, req, res) {
        Passport.authenticate(strategy, {})(req, res, req.next);
    };

    /**
     * Verify that auth credentials which have been passed by a 3rd
     * party are authentic.
     * @param  {Object}   options - Parameters passed from request
     * @param  {Object}   req     - The request object
     * @param  {Object}   res     - The response object
     * @param  {Function} cb      - A callback function -> cb(err, results)
     * @return void
     */
    PassportSSO.verify = function(options, req, res, cb) {
        var provider = options.provider || false,
            strategy = options.strategy || false,
            code     = options.code     || false,
            profile  = options.profile  || {
                provider : provider,
                strategy : strategy,
                code     : code
            };

        if (options.json && profile.accessToken) {
            strategy = Passport._strategy(strategy);

            if (!strategy) {
                return cb(true);
            }

            strategy.userProfile(profile.accessToken, function(err, providerProfile) {
                if (err || !providerProfile) {
                    return cb(err);
                }

                strategy._verify(req, profile.accessToken, false, providerProfile, cb);
            });
        } else {
            Passport.authenticate(strategy, cb)(req, res, req.next);
        }
    };
});
