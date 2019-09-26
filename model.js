const jwtMixin = require('oauth2-server-jwt');
const gentoken = require('./gentoken');
const promisify = require('promisify-any');
const jwt = require('jsonwebtoken');
const InvalidTokenError = require('@compwright/oauth2-server/lib/errors/invalid-token-error');
const InvalidClientError = require('@compwright/oauth2-server/lib/errors/invalid-client-error');
/**
 * Configuration.
 */

var config = {
	clients: [{
		id: 'application',	// TODO: Needed by refresh_token grant, because there is a bug at line 103 in https://github.com/oauthjs/node-oauth2-server/blob/v3.0.1/lib/grant-types/refresh-token-grant-type.js (used client.id instead of client.clientId)
		clientId: 'application',
		clientSecret: 'secret',
		grants: [
			'password',
			'phonenumber',
			'refresh_token'
		],
		redirectUris: []
	}],
	confidentialClients: [{
		clientId: 'confidentialApplication',
		clientSecret: 'topSecret',
		grants: [
			'password',
			'client_credentials'
		],
		redirectUris: []
	}],
	tokens: [],
	users: [{
		username: 'pedroetb',
		password: 'password'
	}]
};

/**
 * Dump the memory storage content (for debug).
 */

var dump = function() {

	console.log('clients', config.clients);
	console.log('confidentialClients', config.confidentialClients);
	console.log('tokens', config.tokens);
	console.log('users', config.users);
};

/*
 * Methods used by all grant types.
 */

var getAccessToken = function(token) {

	var tokens = config.tokens.filter(function(savedToken) {

		return savedToken.accessToken === token;
	});

	return tokens[0];
};

var getClient = function(clientId, clientSecret) {

	var clients = config.clients.filter(function(client) {

		return client.clientId === clientId && client.clientSecret === clientSecret;
	});

	var confidentialClients = config.confidentialClients.filter(function(client) {

		return client.clientId === clientId && client.clientSecret === clientSecret;
	});

	return clients[0] || confidentialClients[0];
};

var saveToken = function(token, client, user) {

	token.client = {
		id: client.clientId
	};

	token.user = {
		username: user.username
	};

	config.tokens.push(token);

	return token;
};

// currently using symmetric key
var accessTokenSecret ='abcde';                   // String (required)
var refreshTokenSecret = '12345';                 // String (required)
var issuer = 'fabrikam.com';                      // String (required)
var userId = 'id';                                // String
var algorithms = ['HS256'];


// This is where we implement the jwt tokens
const accessToken = gentoken({
	type: 'accessToken',
	secret: accessTokenSecret,
	issuer, userId
});

    
const refreshToken = gentoken({
	type: 'refreshToken',
	secret: refreshTokenSecret,
	issuer, userId
});

const signAsync = promisify(jwt.sign, 3);
const verifyAsync = promisify(jwt.verify, 3);

var saveToken2 = async function(token, client, user) {
	const newToken = { ...token, client, user: user.username };

	// eslint-disable-next-line no-unused-vars
	const { payload, secret, iat, nbf, exp, ...params } = accessToken(token, client, user);
	newToken.accessToken = await signAsync(payload, secret, params);

	if (token.refreshToken) {
		// eslint-disable-next-line no-unused-vars
		const { payload, secret, iat, nbf, exp, ...params } = refreshToken(token, client, user);
		newToken.refreshToken = await signAsync(payload, secret, params);
	}

	return newToken;
};

/*
 * Method used only by password grant type.
 */

var getUser = function(username, password) {

	var users = config.users.filter(function(user) {

		return user.username === username && user.password === password;
	});

	return users[0];
};

/*
 * Method used only by client_credentials grant type.
 */

var getUserFromClient = function(client) {

	var clients = config.confidentialClients.filter(function(savedClient) {

		return savedClient.clientId === client.clientId && savedClient.clientSecret === client.clientSecret;
	});

	return clients.length;
};

/*
 * Methods used only by refresh_token grant type.
 */

var getRefreshToken = function(refreshToken) {

	var tokens = config.tokens.filter(function(savedToken) {

		return savedToken.refreshToken === refreshToken;
	});

	if (!tokens.length) {
		return;
	}

	return tokens[0];
};

var getRefreshToken2 = async function(token) {
	try {
		var { exp, aud, type, scope, user } = await verifyAsync(token, refreshTokenSecret, {
			algorithms,
			issuer
		});
	} catch (e) {
		throw new InvalidTokenError();
	}

	if (type !== 'refreshToken') {
		throw new InvalidTokenError();
	}

	// not sure what this code is for

	// if (this.getClient) {
	// 	try {
	// 		var client = aud && await this.getClient(aud, null);
	// 		if (!client) {
	// 			throw new Error();
	// 		}
	// 	} catch (e) {
	// 		throw new InvalidClientError();
	// 	}
	// }

	return {
		refreshToken: token,
		refreshTokenExpiresAt: new Date(exp * 1000),
		scope,
		client: {id: aud},
		// workaround because I commented the above code
		// client: client || { id: aud },
		user
	};
};

var revokeToken = function(token) {

	config.tokens = config.tokens.filter(function(savedToken) {

		return savedToken.refreshToken !== token.refreshToken;
	});

	var revokedTokensFound = config.tokens.filter(function(savedToken) {

		return savedToken.refreshToken === token.refreshToken;
	});

	return !revokedTokensFound.length;
};

/**
 * Export model definition object.
 */

module.exports = {
	getAccessToken: getAccessToken,
	getClient: getClient,
	saveToken: saveToken2,                      //switch to JWT implementation
	getUser: getUser,
	getUserFromClient: getUserFromClient,
	getRefreshToken: getRefreshToken2,          //switch to JWT implementation
	revokeToken: revokeToken,
	// https://github.com/compwright/oauth2-server-jwt
	//  enable this to use jwtMixin's implementation of JWT tokens
	// ...jwtMixin({
	// 	accessTokenSecret :'abcde',                  // String (required)
	// 	refreshTokenSecret : '12345',                 // String (required)
	// 	authorizationCodeSecret : '54321',            // String (required)
	// 	issuer : 'realtor.com',                             // String (required)
	// 	userId: 'id',                       // String
	// 	algorithms: ['HS256']               // Array[String]
	// })
};
