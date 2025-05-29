const OpenIDConnectStrategy = require('passport-openidconnect').Strategy;
const crypto   = require('crypto');
const base64url = require('base64url');

/* ------------------------------------------------------------------ */
/*  REDIS-BACKED STATE STORE                                          */
/* ------------------------------------------------------------------ */
class RedisStateStore {
  constructor(redis) { this.redis = redis; }

  /* Called during the AUTHORISATION redirect */
  store(req, cb) {
    const handle = crypto.randomBytes(16).toString('hex');   // state nonce
    /* We’re **not** putting the PKCE verifier here any more – that is
       generated in `authorizationParams()` so we only create ONE of them. */
    this.redis.set(`state:${handle}`, '1', { EX: 900 })
      .then(() => { console.log('[StateStore] saved', handle); cb(null, handle); })
      .catch(cb);
  }

  /* Called on the CALLBACK request to prove the nonce round-tripped */
  verify(req, handle, cb) {
    this.redis.getDel(`state:${handle}`)
      .then(val => {
        const ok = !!val;
        console.log('[StateStore] verify', handle, ok ? '✓' : '✗');
        cb(null, ok);
      })
      .catch(cb);
  }
}

/* ------------------------------------------------------------------ */
/*  MAIN STRATEGY EXTENSION                                           */
/* ------------------------------------------------------------------ */
class AudkenniStrategy extends OpenIDConnectStrategy {
  constructor(options, verify) {
    super(options, verify);
    this.name         = options.name || 'audkenni';
    this._pkceMethod  = options.pkce || 'S256';
    console.log('[Audkenni] initialised with', JSON.stringify(options, null, 2));
  }

  /* --------------------------------------------------------------- */
  /* Passport entry-point                                            */
  /* --------------------------------------------------------------- */
  authenticate(req, opt = {}) {
    /* --- enrich scope ------------------------------------------------ */
    if (this._options.relatedParty) {
      const baseScope = opt.scope || this._options.scope || '';
      opt.scope = `${baseScope} RELATEDPARTY:${this._options.relatedParty}`;
    }

    /* --- token phase ------------------------------------------------- */
    if (req.query?.code) {
      console.log('[Audkenni] TOKEN phase, state=', req.query.state);
      return this._attachCodeVerifierAndGo(req, opt);
    }

    /* --- authorisation phase ---------------------------------------- */
    console.log('[Audkenni] AUTH phase → passport redirect');
    super.authenticate(req, opt);               // Passport will call our
                                                //   authorizationParams()
  }

  /* --------------------------------------------------------------- */
  /* add code_verifier before we hand control back to passport       */
  /* --------------------------------------------------------------- */
  async _attachCodeVerifierAndGo(req, opt) {
    const state = req.query.state;
    const key   = `pkceCodeVerifier:${state}`;
    const vfy   = await req.redisClient.getDel(key);   // get & delete

    console.log('[Audkenni] redis GETDEL', key, '→', vfy || '<none>');
    if (!vfy) { return this.error(new Error('PKCE verifier missing')); }

    /* inject into oauth2 token call */
    const orig = this._oauth2.getOAuthAccessToken;
    this._oauth2.getOAuthAccessToken = (code, params, cb) => {
      params.code_verifier = vfy;
      orig.call(this._oauth2, code, params, cb);
    };

    super.authenticate(req, opt);
  }

  /* --------------------------------------------------------------- */
  /* Build extra query params for the *authorisation* redirect       */
  /* --------------------------------------------------------------- */
  authorizationParams(opt = {}) {
    const params = {};

    /* Passport (because `state:true`) has just set `opt.state` */
    const state = opt.state;
    console.log('[Audkenni] authorizationParams for state', state);

    /* ---- PKCE generation ------------------------------------- */
    const verifier  = base64url(crypto.pseudoRandomBytes(32));
    const challenge = this._pkceMethod === 'S256'
        ? base64url(crypto.createHash('sha256').update(verifier).digest())
        : verifier;

    params.code_challenge        = challenge;
    params.code_challenge_method = this._pkceMethod;

    /* ---- persist the verifier for the callback --------------- */
    const key = `pkceCodeVerifier:${state}`;
    opt.req.redisClient.set(key, verifier, { EX: 900 })
      .then(() => console.log('[Audkenni] saved verifier', key))
      .catch(err => console.error('[Audkenni] redis error', err));

    return params;
  }
}

/* ------------------------------------------------------------------ */
/*  EXPORT – factory that plugs everything into Passport              */
/* ------------------------------------------------------------------ */
module.exports = function PassportSSOFactory(redis) {
  const passport   = require('passport');
  const PassportSSO = {};

  /* ------------------------------------------------------------- */
  PassportSSO.loadStrategies = function (providers, authorizeCb, loginCb) {
    providers.forEach(p => {
      if (p.provider !== 'audkenni') { return; }

      /* Strategy-level options */
      const strategyOptions = {
        issuer:           p.issuer,
        authorizationURL: p.authorizationURL,
        tokenURL:         p.tokenURL,
        userInfoURL:      p.userInfoURL,
        clientID:         p.clientID,
        clientSecret:     p.clientSecret,
        callbackURL:      p.callbackUrl,

        scope:            'openid profile signature',
        pkce:             'S256',

        state:  true,
        store:  new RedisStateStore(redis),

        passReqToCallback: true
      };

      passport.use(
        p.name,
        new AudkenniStrategy(strategyOptions, authorizeCb)
      );

      console.log('[Audkenni] Strategy registered →', p.name);
    });
  };

  /* other PassportSSO helpers unchanged … */

  return PassportSSO;
};
