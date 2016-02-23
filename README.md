# passport-sso
Single signon with Node.js using passport

This project is intended to handle mutlidomain logins via REST service calls or standard oauth redirects. I've created an issue and pull request on the passport github page pertaining to ajax logins using 3rd party vendors,
so when using this package, you may also want to use the forked passport-oauth2 version at https://github.com/mattmccarty/passport-oauth2. If the owner of passport accepts my pull request, I will remove this message
and it will then be safe to use the normal passport-sso npm module.

Track the issue and pull request:
https://github.com/jaredhanson/passport-oauth2/issues/51
https://github.com/jaredhanson/passport-oauth2/pull/52

I'm working on a project that requires passport-sso, so expect it to constantly evolve for the next month or so.

