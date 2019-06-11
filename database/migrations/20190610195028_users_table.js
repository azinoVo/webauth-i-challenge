
exports.up = function(knex, Promise) {
  return knex.schema.createTable('users', user => {
      user
        .increments(); // creates auto-incrementing primary key

      user
        .string('username', 255)
        .notNullable()
        .unique();

      user
        .string('password', 255)
        .notNullable();
  })
};

exports.down = function(knex, Promise) {
  return knex.schema.dropTableIfExists('users');
};