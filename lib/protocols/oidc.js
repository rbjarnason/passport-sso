module.exports = function (req, issuer, profile, context, idToken, accessToken, refreshToken, params, verified) {
  console.log("OIDC protocol handler called");
  console.log("Issuer:", issuer);
  console.log("Profile:", JSON.stringify(profile, null, 2));
  console.log("Context:", JSON.stringify(context, null, 2));
  console.log("Params:", JSON.stringify(params, null, 2));

  var query = {
    protocol: "oidc",
    provider: "oidc",
    strategy: (req.params && req.params.strategy) ||
              (req.body && req.body.strategy)   ||
              (req.query && req.query.strategy),
    name: profile.displayName,
    nationalRegisterId: profile.nationalRegisterId,
    ssn: profile.nationalRegisterId
  };

  // If you have access to tokens, you might add them here
  // query.tokens = { accessToken: profile.accessToken };

  console.log("OIDC query object:", JSON.stringify(query, null, 2));

  // Always call verified with the query object
  return verified(null, query);
};
