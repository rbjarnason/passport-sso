module.exports = function (req, issuer, profile, verified) {
  console.log("OIDC protocol handler called");
  console.log("Issuer:", issuer);
  console.log("Profile:", JSON.stringify(profile, null, 2));

  var query = {
    protocol: "oidc",
    strategy: req.param("strategy"),
    provider: issuer,
  };


  // If you have access to tokens, you might add them here
  // query.tokens = { accessToken: profile.accessToken };

  console.log("OIDC query object:", JSON.stringify(query, null, 2));

  // Always call verified with the query object
  return verified(null, query);
};
