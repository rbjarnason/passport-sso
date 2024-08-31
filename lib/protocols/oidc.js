module.exports = function (req, issuer, profile, verified) {
  console.log("OIDC protocol handler called");
  console.log("Issuer:", issuer);
  console.log("Profile:", JSON.stringify(profile, null, 2));

  var query = {
    protocol: "oidc",
    strategy: req.param("strategy"),
    provider: issuer,
  };

  if (profile.sub) query.identifier = profile.sub;
  if (profile.name) query.nameDisplay = profile.name;
  if (profile.given_name) query.nameFirst = profile.given_name;
  if (profile.family_name) query.nameLast = profile.family_name;
  if (profile.email) query.email = profile.email;
  if (profile.picture) query.image = profile.picture;
  if (profile.gender) query.gender = profile.gender;
  if (profile.locale) query.language = profile.locale;

  // If you have access to tokens, you might add them here
  // query.tokens = { accessToken: profile.accessToken };

  console.log("OIDC query object:", JSON.stringify(query, null, 2));

  // Always call verified with the query object
  return verified(null, query);
};
