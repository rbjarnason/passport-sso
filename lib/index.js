const crypto = require("crypto");

function generateCodeVerifier() {
  return crypto
    .randomBytes(32)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash("sha256");
  hash.update(codeVerifier);
  return hash
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

module.exports = function () {
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
  var Passport = require("passport");

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
  PassportSSO.init = function (hosts, providers, callbacks) {
    if (!Array.isArray(hosts)) return;
    if (!Array.isArray(providers)) return;
    if (typeof callbacks !== "object") return;

    Hosts = hosts;
    this.loadStrategies(providers, callbacks.authorize, callbacks.login);
  };

  /**
   * Load all stratgies from an array of provider objects
   * @param  {Array} providers - An array of provider configuration objects
   * @return void
   */
  PassportSSO.loadStrategies = function (providers, authorize, login) {
    Passport.protocols = require("./protocols");

    for (var i = 0; i < providers.length; i++) {
      var providerOpts = providers[i],
        strategyPackage = null,
        strategyObject = null,
        strategy = null;

      if (
        !providerOpts.provider ||
        !providerOpts.strategyPackage ||
        !providerOpts.strategyObject
      ) {
        continue;
      }

      var passportOpts;

      if (providerOpts.provider == "saml") {
        passportOpts = this.getPassportSamlOptions(providerOpts);
      } else if (
        providerOpts.provider == "oidc" ||
        providerOpts.provider == "audkenni"
      ) {
        passportOpts = this.getPassportOidcOptions(providerOpts);
      } else {
        passportOpts = this.getPassportOAuthOptions(providerOpts);
      }

      console.log(
        `1-------------------> ${JSON.stringify(passportOpts, null, 2)}`
      );

      switch (passportOpts.provider) {
        case "bearer":
          if (typeof authorize === "function") {
            Providers[passportOpts.name] = providerOpts;
            Passport.use(
              passportOpts.name,
              new passportOpts.strategy(authorize)
            );
          }
          continue;
        case "local":
          if (typeof login === "function") {
            Providers[passportOpts.name] = providerOpts;
            passportOpts.usernameField = "identifier";
            passportOpts.passReqToCallback = true;
            Passport.use(
              passportOpts.name,
              new passportOpts.strategy(passportOpts, login)
            );
          }
          continue;
        case "saml":
          passportOpts.option = providerOpts.options;
          Providers[passportOpts.name] = providerOpts;
          Passport.use(
            passportOpts.name,
            new passportOpts.strategy(
              passportOpts.options,
              Passport.protocols[passportOpts.protocol]
            )
          );
          continue;
        case "oidc":
        case "audkenni":
          Providers[passportOpts.name] = providerOpts;

          const StrategyClass = passportOpts.strategy;

          class AudkenniStrategy extends StrategyClass {
            constructor(options, verify) {
              super(options, verify);
              this.name = passportOpts.name;
            }

            authenticate(req, options) {
              if (req.query && req.query.code) {
                // Callback phase
                if (!req.session || !req.session.codeVerifier) {
                  return this.error(new Error("Missing code_verifier"));
                }
                options.code_verifier = req.session.codeVerifier;
                delete req.session.codeVerifier;
                req.session.save((err) => {
                  if (err) {
                    console.error("Error saving session:", err);
                  }
                });
              } else {
                // Authorization phase
                const codeVerifier = generateCodeVerifier();
                const codeChallenge = generateCodeChallenge(codeVerifier);

                if (!req.session) {
                  req.session = {};
                }
                req.session.codeVerifier = codeVerifier;
                req.session.save((err) => {
                  if (err) {
                    console.error("Error saving session:", err);
                  }
                });

                options = {
                  ...options,
                  scope: this._options.scope || "openid profile",
                  code_challenge: codeChallenge,
                  code_challenge_method: "S256",
                //  acr_values: this._options.acrValues || "sim",
                };
              }

              super.authenticate(req, options);
            }

            authorizationParams(options) {
              return {
                ...super.authorizationParams(options),
                code_challenge: options.code_challenge,
                code_challenge_method: options.code_challenge_method,
                acr_values: options.acr_values,
              };
            }

            tokenParams(options) {
              return {
                ...super.tokenParams(options),
                code_verifier: options.code_verifier,
              };
            }
          }

          const strategyOptions = {
            ...passportOpts.options,
            scope: "openid profile signature RELATEDPARTY:exampleclient",
            acrValues: "sim", // or 'nexus' or 'default'
          };

          Passport.use(
            passportOpts.name,
            new AudkenniStrategy(
              strategyOptions,
              Passport.protocols[passportOpts.protocol]
            )
          );

          console.log(
            `Audkenni OIDC Strategy created for ${passportOpts.name}`
          );
          continue;
        case "oidcold":
        case "audkenniold":
          Providers[passportOpts.name] = providerOpts;

          // Create the strategy
          const strategy = new passportOpts.strategy(
            passportOpts.options,
            Passport.protocols[passportOpts.protocol]
          );

          // Extend the strategy with PKCE support
          strategy.authorizationParams = function (options) {
            const codeVerifier = generateCodeVerifier();
            const codeChallenge = generateCodeChallenge(codeVerifier);

            // Store the code verifier for later use
            if (options.req && options.req.session) {
              options.req.session.codeVerifier = codeVerifier;
            }

            return {
              code_challenge: codeChallenge,
              code_challenge_method: "S256",
            };
          };

          // Add code verifier to token request
          strategy.tokenParams = function (options) {
            return {
              code_verifier: options.req.session.codeVerifier,
            };
          };

          Passport.use(passportOpts.name, strategy);
          console.log(
            `OIDC Strategy with PKCE support created for ${passportOpts.name}`
          );
          continue;
        default:
          Providers[passportOpts.name] = providerOpts;
          if (passportOpts.protocol === "openid") {
            passportOpts.realm = baseUrl;
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
    }
  };

  /**
   * Build passport provider/strategy object from a oauth provider's configuration object
   * @param  {Object} providerOpts - Configuration options from a provider
   * @return void
   */
  PassportSSO.getPassportOAuthOptions = function (providerOpts) {
    var passportOpts = {
      provider: providerOpts.provider,
      name: providerOpts.name,
      protocol: providerOpts.protocol,
      strategy: require(providerOpts.strategyPackage)[
        providerOpts.strategyObject
      ],
      options: {
        clientID: providerOpts.clientID || "false",
        clientSecret: providerOpts.clientSecret || "false",
        scope: providerOpts.scope || [],
        profileFields: providerOpts.fields || null,
        callbackURL: providerOpts.urlCallback || "false",
      },
    };

    if (passportOpts.options) {
      if (passportOpts.options.passReqToCallback === undefined) {
        passportOpts.options.passReqToCallback = true;
      } else {
        passportOpts.options.passReqToCallback =
          providerOpts.options.passReqToCallback;
      }

      if (passportOpts.options.callbackURL.toLowerCase() === "postmessage") {
        passportOpts.options.autoResolveCallback = false;
      }
    }

    return passportOpts;
  };

  /**
   * Build passport provider/strategy object from a oauth provider's configuration object
   * @param  {Object} providerOpts - Configuration options from a provider
   * @return void
   */
  PassportSSO.getPassportSamlOptions = function (providerOpts) {
    var passportOpts = {
      provider: providerOpts.provider,
      name: providerOpts.name,
      protocol: providerOpts.protocol,
      strategy: require(providerOpts.strategyPackage)[
        providerOpts.strategyObject
      ],
      options: {
        entryPoint: providerOpts.entryPoint || null,
        callbackUrl: providerOpts.callbackUrl || null,
        cert: providerOpts.cert || null,
        audience: providerOpts.audience || null,
        issuer: providerOpts.issuer || null,
        identifierFormat: providerOpts.identifierFormat || null,
        certInPemFormat: true,
        signatureAlgorithm: "sha256",
      },
    };

    return passportOpts;
  };

  /**
   * Return a provider object by searching all providers by the providerName
   * @param  {String} providerName - Name of the provider to search for
   *                                 this is found in the Providers[x].name object
   * @return {Object} || null
   */
  PassportSSO.getProvider = function (providerName) {
    if (typeof providerName !== "string" || Providers.length <= 0) {
      return null;
    }

    for (var provider in Providers) {
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
  PassportSSO.authenticate = function (strategy, options, req, res, cb) {
    Passport.authenticate(strategy, options)(req, res, cb);
  };

  /**
   * Verify that auth credentials which have been passed are authentic.
   * @param  {String}   strategy - The strategy name. This would have been specified
   *                               in the strategy's configuration that was passed to
   *                               PassportSSO.init()
   * @param  {String}   token    - (Optional) Access token if user has been authenticated in the UI already
   * @param  {Object}   options  - Parameters passed from request
   * @param  {Object}   req      - The request object
   * @param  {Object}   res      - The response object
   * @param  {Function} cb       - A callback function -> cb(err, user, info)
   * @return void
   */
  PassportSSO.callback = function (strategy, token, options, req, res, cb) {
    if (typeof token === "string" && token.length > 0) {
      return this.profile(strategy, token, req, cb);
    }

    Passport.authenticate(strategy, options, function (err, user) {
      if (err) {
        return cb(err, false, false);
      }
      if (!user) {
        return cb("passportsso.error.user", false);
      }

      return cb(false, user);
    })(req, res, cb);
  };

  PassportSSO.getPassportOidcOptions = function (providerOpts) {
    console.log(
      `2-------------------> ${JSON.stringify(providerOpts, null, 2)}`
    );
    var passportOpts = {
      provider: providerOpts.provider,
      name: providerOpts.name,
      protocol: providerOpts.protocol,
      strategy: require(providerOpts.strategyPackage)[
        providerOpts.strategyObject
      ],
      options: {
        issuer: providerOpts.issuer,
        authorizationURL: providerOpts.authorizationURL,
        tokenURL: providerOpts.tokenURL,
        userInfoURL: providerOpts.userInfoURL,
        clientID: providerOpts.clientID,
        clientSecret: providerOpts.clientSecret,
        callbackURL: providerOpts.callbackUrl,
        scope: providerOpts.scope || ["openid", "profile", "email"],
      },
    };

    if (passportOpts.options) {
      passportOpts.options.passReqToCallback = true;
    }

    return passportOpts;
  };

  /**
   * Get user profile using an access token
   * @param  {String}   strategy - The strategy name. This would have been specified
   *                               in the strategy's configuration that was passed to
   *                               PassportSSO.init()
   * @param  {String}   token    - Access token provided by auth vendor
   * @param  {Object}   req      - The request object
   * @param  {Function} cb       - A callback function -> cb(err, user, info)
   * @return void
   */
  PassportSSO.profile = function (strategy, token, req, cb) {
    strategy = Passport._strategies[strategy];
    if (!strategy) {
      return cb("passportsso.error.strategy", false);
    }

    var skipProfile = strategy._skipUserProfile;
    if (
      skipProfile ||
      strategy.userProfile == undefined ||
      typeof strategy.userProfile !== "function"
    ) {
      return cb("passportsso.error.profile", false);
    }

    strategy.userProfile(token, function (err, profile) {
      if (err) {
        return cb(err);
      }

      if (strategy._passReqToCallback) {
        return strategy._verify(req, token, null, profile, cb);
      }

      return strategy._verify(token, null, profile, cb);
    });
  };

  return PassportSSO;
};
