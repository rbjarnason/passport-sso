const OpenIDConnectStrategy = require("passport-openidconnect").Strategy;
const crypto = require("crypto");
const base64url = require("base64url");

class AudkenniStrategy extends OpenIDConnectStrategy {
  constructor(options, verify) {
    super(options, verify);
    this.name = options.name || "audkenni";
    this._pkceMethod = options.pkce || "S256";
    this._options = options;
    console.log(`AudkenniStrategy initialized with options:`, JSON.stringify(options, null, 2));
  }

  authenticate(req, options) {
    options = options || {};
    console.log("AudkenniStrategy.authenticate called with options:", JSON.stringify(options, null, 2));

    if (this._options && this._options.acrValues) {
      options.acr_values = this._options.acrValues;
    }

    if (this._options && this._options.relatedParty) {
      const scope = options.scope || this._options.scope || "";
      options.scope = `${scope} RELATEDPARTY:${this._options.relatedParty}`;
    }

    if (!req.query || !req.query.code) {
      // Authorization phase
      console.log("AudkenniStrategy: Entering authorization phase");
      const params = this.authorizationParams(req, options);
      options = { ...options, ...params };
    } else {
      // Token phase
      console.log("AudkenniStrategy: Entering token phase");
      if (req.session && req.session.pkceCodeVerifier) {
        options.code_verifier = req.session.pkceCodeVerifier;
        delete req.session.pkceCodeVerifier;
        console.log("AudkenniStrategy: Code verifier retrieved from session");
      } else {
        console.warn("AudkenniStrategy: Missing pkceCodeVerifier in session");
      }
    }

    super.authenticate(req, options);
  }

  authorizationParams(req, options) {
    const params = super.authorizationParams(options);

    var verifier, challenge;
    if (this._pkceMethod) {
      verifier = base64url(crypto.pseudoRandomBytes(32));
      switch (this._pkceMethod) {
        case "plain":
          challenge = verifier;
          break;
        case "S256":
          challenge = base64url(
            crypto.createHash("sha256").update(verifier).digest()
          );
          break;
        default:
          console.error(
            `AudkenniStrategy: Unsupported PKCE method: ${this._pkceMethod}`
          );
          return this.error(
            new Error(
              "Unsupported code verifier transformation method: " +
                this._pkceMethod
            )
          );
      }
      params.code_challenge = challenge;
      params.code_challenge_method = this._pkceMethod;
      if (req.session) {
        req.session.pkceCodeVerifier = verifier;
        console.log(
          `AudkenniStrategy: PKCE challenge generated using ${this._pkceMethod} method`
        );
      } else {
        console.warn("AudkenniStrategy: No session available for storing PKCE verifier");
      }
    }

    return params;
  }

  tokenParams(options) {
    const params = super.tokenParams(options);
    if (options.code_verifier) {
      params.code_verifier = options.code_verifier;
      console.log("AudkenniStrategy: Code verifier added to token params");
    } else {
      console.warn(
        "AudkenniStrategy: No code verifier available for token request"
      );
    }
    return params;
  }
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
          const strategyOptions = {
            issuer: providerOpts.issuer,
            authorizationURL: providerOpts.authorizationURL,
            tokenURL: providerOpts.tokenURL,
            userInfoURL: providerOpts.userInfoURL,
            clientID: providerOpts.clientID,
            clientSecret: providerOpts.clientSecret,
            callbackURL: providerOpts.callbackUrl,
            scope: "openid profile signature",
            pkce: "S256",
            acrValues: providerOpts.acrValues || "sim",
            relatedParty: providerOpts.clientID, // or another identifier if needed
            passReqToCallback: true,
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
