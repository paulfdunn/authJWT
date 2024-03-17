# authJWT
This package is a GO (GOLANG) package that provides JWT authentication.

This package is used by github.com/paulfdunn/rest-app, see that project for example usage.

Key features:
* Authentication is handled using JWT (JSON Web Tokens).
* Authentication supports 2 models: anyone can create a login, or only a registered user can create a new login. The later is the default in the example app.
* Authentication supports REGEX based validation/rules for passwords.

