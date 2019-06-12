const knex = require('knex');

const knexConfig = require('../knexfile.js');

module.exports = knex(knexConfig.development);

// this sets up the development environment so you can import this
// wherever you need the server.
