const bcrypt = require('bcryptjs');

let user = {};
const hash = bcrypt.hashSync('password', 10);
user.password = hash;
exports.seed = function(knex, Promise) {

  return knex('users').truncate()
    .then(function () {
      return knex('users').insert([
        { username: 'IanMichael', password: user.password },
      ]);
    });
};
