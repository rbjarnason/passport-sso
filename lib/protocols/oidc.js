module.exports = function (user, cb) {
    user.provider = 'oidc';
    return cb(null, user);
 };

/*module.exports = function (tokenSet, userInfo, done) {
  if (userInfo && tokenSet) {
      var query = {
          protocol: 'oidc',
          strategy: req.param('strategy'),
          tokens: {
              accessToken: tokenSet.access_token,
              idToken: tokenSet.id_token,
              refreshToken: tokenSet.refresh_token
          }
      };

      if (userInfo.sub)                 query.identifier = userInfo.sub;
      if (userInfo.provider)            query.provider = userInfo.provider;
      if (userInfo.name)                query.nameDisplay = userInfo.name;
      if (userInfo.given_name)          query.nameFirst = userInfo.given_name;
      if (userInfo.family_name)         query.nameLast = userInfo.family_name;
      if (userInfo.email)               query.email = userInfo.email;
      if (userInfo.picture)             query.image = userInfo.picture;
      if (userInfo.gender)              query.gender = userInfo.gender;
      if (userInfo.locale)              query.language = userInfo.locale;
      if (userInfo.nationalRegisterId)  query.nationalRegisterId = userInfo.nationalRegisterId;

  } else {
      console.error(`Error: No tokenSet or userInfo provided`);
      var query = {};
  }

  return done(null, query);
};*/