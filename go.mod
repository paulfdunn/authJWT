module github.com/paulfdunn/authJWT

go 1.16

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/paulfdunn/db v0.0.3
	github.com/paulfdunn/logh v0.2.5
	github.com/paulfdunn/neth v0.0.1
	github.com/paulfdunn/osh v0.0.1
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
)

// replace (
// 	github.com/paulfdunn/db => /home/paulfdunn/go/src/github.com/paulfdunn/db
// 	github.com/paulfdunn/authJWT => /home/paulfdunn/go/src/github.com/paulfdunn/authJWT
// 	github.com/paulfdunn/logh => /home/paulfdunn/go/src/github.com/paulfdunn/logh
// 	github.com/paulfdunn/osh => /home/paulfdunn/go/src/github.com/paulfdunn/osh
// 	github.com/paulfdunn/neth => /home/paulfdunn/go/src/github.com/paulfdunn/neth
// )