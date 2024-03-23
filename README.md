# authJWT
This package is a GO (GOLANG) package that provides JWT authentication.

This package is used by github.com/paulfdunn/rest-app, see that project for example usage.

Key features:
* Authentication is handled using JWT (JSON Web Tokens).
* Authentication supports 2 models: anyone can create a login, or only a registered user can create a new login. The later is the default in the example app.
* Authentication supports REGEX based validation/rules for passwords.
* All authentication data and tokens are stored in a SQLITE database.
* Multiple tokens are allowed per user, allowing login/logout from different devices.
* The provided wrappers log all DELETE/POST/PUT calls to an audit log.

## Security
Use only HTTPS to prevent tokens being stolen in-flight; I.E. public wi-fi. Callers should not store the tokens. Use the token for the session only; the user can save their credentials via their browser, if they chose, to make logging in easier. Do also allow your users access to logout-all, as well as to the number of tokens available for their ID.

## Usage
Applications only need call Init with a Config object, and optional http.ServeMux. If a mux is provided, the paths in the config object are wrapped in the authJWT handlers and registerd. If no mux is provided in the Init call, applications must wrap their handlers using HandlerFuncAuthJWTWrapper.

Once initialized, authJWT handlers will respond to the specified paths to let callers: create/delete/update their authentication, login/logout (logout from the calling device)/logout-all (logout of any device), refresh (extend the time a token is valid), or get information about their authentication.

For detailed usage and an example application, see github.com/paulfdunn/rest-app.
