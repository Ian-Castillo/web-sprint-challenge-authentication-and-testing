const router = require('express').Router();
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const secrets = require('../config/secrets');
const authenticate = require('./authenticate-middleware');
const jwt = require('jsonwebtoken');

function genToken(user) {
  const payload = {
    username: user.username,
  };

  const options = { expiresIn: '24h' };

  const token = jwt.sign(payload, secrets.jwtSecret, options);

  return token;
}; 

router.get('/', (req, res) => {
  res.send('Hello from Express');
});

router.post('/register', (req, res) => {
  // implement registration
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);
  user.password = hash;

  Users.add(user)
    .then(saved => {
      const token = genToken(saved);
      res.status(201).json({ created_user: saved, token: token });
    })
    .catch(err => {
      res.status(500).json({ error: err });
    });
});

//impliment login
router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username }) //return an array that matches the username.
    .first()
    .then(user => { // check that passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = genToken(user);
        res.status(200).json({ message: `Welcome ${user.username}!`, token: token });
      } else {
        // we will return 401 if the password or username are invalid
        // we don't want to let attackers know when they have a good username
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
}); 

module.exports = router;
