const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('../database/dbConfig');



const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("Server Works!");
});


server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);
  user.password = hash;

  if (!user.username || !user.password) {
    res.status(500).json({ message: "Please provide username and password!" })
  } else {
    db('users')
      .insert(user, 'id')
      .then(ids => {
        const [id] = ids;

        db('users').where({ id }).first().then((user) => {
          res.status(200).json(user);
        });
      })
      .catch(err => {
        res.status(500).json(err);
      })
  }
});


server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  if (!username || !password) {
    res.status(500).json({ message: "Please provide username and password!" })

  } else {
    db('users')
      .where({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          res.status(200).json({ message: "Login Successful!" })
        } else {
          res.status(401).json({ message: "Login Failure. Please Provide correct user information!" })
        }
      })
      .catch(err => {
        res.status(404).json(err);
      })
  }

});

server.get('/api/users', checkCredentials, (req, res) => {

  db('users')
    .then(users => {
      if (users.length > 0) {
        res.status(200).json(users)
      } else {
        res.status(500).json({ message: "None are Found" })
      }
    })
    .catch(err => {
      res.status(500).json(err);
    })
});

// Middleware

function checkCredentials(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    db('users')
      .where({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(400).json({ message: 'Please provide credentials' });
  }
};

module.exports = server;
