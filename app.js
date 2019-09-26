// https://github.com/pedroetb/node-oauth2-server-example

// complement with https://github.com/compwright/oauth2-server-jwt
const OAuth2Server = require('@compwright/oauth2-server');
var express = require('express'),
	bodyParser = require('body-parser'),
	// OAuth2Server = require('oauth2-server'),
	Request = OAuth2Server.Request,
	Response = OAuth2Server.Response;

var PhoneNumberGrantType = require('./PhoneNumberGrantType')
var EmailGrantType = require('./EmailGrantType')

var app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.use(bodyParser.json());

app.oauth = new OAuth2Server({
	model: require('./model.js'),
	accessTokenLifetime: 60 * 60,
	allowBearerTokensInQueryString: true
});

app.all('/oauth/token', obtainToken);

app.get('/', authenticateRequest, function(req, res) {

	res.send('Congratulations, you are in a secret area!');
});

app.listen(3000);

let options = {
	requireClientAuthentication: {password: false},
	extendedGrantTypes: {
		'phonenumber': PhoneNumberGrantType,
		'password': EmailGrantType
	}
};
	

function obtainToken(req, res) {

	var request = new Request(req);
	var response = new Response(res);

	return app.oauth.token(request, response, options)
		.then(function(token) {

			res.json(token);
		}).catch(function(err) {

			res.status(err.code || 500).json(err);
		});
}

function authenticateRequest(req, res, next) {

	var request = new Request(req);
	var response = new Response(res);

	return app.oauth.authenticate(request, response)
		.then(function(token) {

			next();
		}).catch(function(err) {

			res.status(err.code || 500).json(err);
		});
}
