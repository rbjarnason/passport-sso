module.exports = (function() {
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
     * An array of objects containing supported hostnames and their settings
     * @type {Array}
     */
    var Hosts = [];

    /**
     * Passport providers and their configurations
     * @type {Array}
     */
    var Providers = [];

    /**
     * Initialize PassportSSO
     * @param  {Array}    hosts     - An array of objects containing supported hosts
     * @param  {Array}    providers - An array of provider configuration objects
     * @param  {Object}   callbacks - An object containing a authorize and login callback
     * @return void
     */
    PassportSSO.init = function(hosts, providers, callbacks) {
        if (!Array.isArray(hosts))          return;
        if (!Array.isArray(providers))      return;
        if (typeof callbacks !== 'object')  return;

        Hosts = hosts;
        this.loadStrategies(providers, callbacks.authorize, callbacks.login);
    };

    /**
     * Load all stratgies from an array of provider objects
     * @param  {Array} providers - An array of provider configuration objects
     * @return void
     */
    PassportSSO.loadStrategies = function(providers, authorize, login) {
        Passport.protocols = require('./protocols');

        for (var i = 0; i < providers.length; i++) {
            var providerOpts    = providers[i],
                strategyPackage = null,
                strategyObject  = null,
                strategy        = null;

            if (
                !providerOpts.provider          ||
                !providerOpts.strategyPackage   ||
                !providerOpts.strategyObject
            ) {
                continue;
            }

            var passportOpts = this.getPassportOptions(providerOpts);
            switch (passportOpts.provider) {
                case 'bearer':
                    if (typeof providerOpts.authorize === 'function') {
                        Providers[passportOpts.name] = providerOpts;
                        Passport.use(passportOpts.name, new passportOpts.strategy(authorize));
                    }
                    continue;
                case 'local':
                    if (typeof providerOpts.login === 'function') {
                        Providers[passportOpts.name] = providerOpts;
                        passportOpts.usernameField    = 'identifier';
                        Passport.use(passportOpts.name, new passportOpts.strategy(passportOpts, login));
                    }
                    continue;
                default:
                   Providers[passportOpts.name] = providerOpts;
                   if (passportOpts.protocol === 'openid') {
                        passportOpts.realm   = baseUrl;
                        passportOpts.profile = true;
                    }

                     Passport.use(
                        passportOpts.name,
                        new passportOpts.strategy(
                            passportOpts.options,
                            Passport.protocols[passportOpts.protocol]
                        )
                    );
                    break;
            }
        };
    };

    /**
     * Build passport provider/strategy object from a provider's configuration object
     * @param  {Object} providerOpts - Configuration options from a provider
     * @return void
     */
    PassportSSO.getPassportOptions = function(providerOpts) {
        var passportOpts = {
            provider : providerOpts.provider,
            name     : providerOpts.name,
            protocol : providerOpts.protocol,
            strategy : require(providerOpts.strategyPackage)[providerOpts.strategyObject],
            scope    : providerOpts.scope || [],
            options: {
                clientID     : providerOpts.clientID     || "false",
                clientSecret : providerOpts.clientSecret || "false",
                callbackURL  : providerOpts.urlCallback  || "false",
                profileFields: providerOpts.fields       || null
            }
        };

        if (passportOpts.options) {
            if (passportOpts.options.passReqToCallback === undefined) {
                passportOpts.options.passReqToCallback = true;
            } else {
                passportOpts.options.passReqToCallback = providerOpts.options.passReqToCallback
            }

            if (passportOpts.options.callbackURL.toLowerCase() === 'postmessage') {
                passportOpts.options.autoResolveCallback = false;
            }
        }

        return passportOpts;
    };

    /**
     * Return a provider object by searching all providers by the providerName
     * @param  {String} providerName - Name of the provider to search for
     *                                 this is found in the Providers[x].name object
     * @return {Object} || null
     */
    PassportSSO.getProvider = function(providerName) {
        if (typeof providerName !== 'string' || Providers.length <= 0) {
            return null;
        }

        for (provider in Providers) {
            if (provider.name && provider.name === providerName) {
                return provider;
            }
        }

        return null;
    };

    /**
     * Redirect the user to a strategy's (i.e: google) login page
     * @param  {String}   strategy - The strategy name. This would have been specified
     *                               in the strategy's configuration that was passed to
     *                               PassportSSO.init()
     * @param  {Object}   options  - Passport authentication options
     * @param  {Object}   req      - The request object
     * @param  {Object}   res      - The response object
     * @param  {Function} cb       - A callback function -> cb(err, results)
     * @return void
     */
    PassportSSO.authenticate = function(strategy, options, req, res, cb) {
        Passport.authenticate(strategy, options)(req, res, cb);
    };

    /**
     * Verify that auth credentials which have been passed by a 3rd
     * party are authentic.
     * @param  {String}   strategy - The strategy name. This would have been specified
     *                               in the strategy's configuration that was passed to
     *                               PassportSSO.init()
     * @param  {Object}   options  - Parameters passed from request
     * @param  {Object}   req      - The request object
     * @param  {Object}   res      - The response object
     * @param  {Function} cb       - A callback function -> cb(err, user, info)
     * @return void
     */
    PassportSSO.callback = function(strategy, options, req, res, cb) {
        Passport.authenticate(strategy, options, function(err, user) {
            if(err) {
                return cb(err, false, false)
            }
            if (!user) {
                return cb("passportsso.error.user", false);
            }

            return cb(false, user);
        })(req, res, cb);
    };

    return PassportSSO;
});
