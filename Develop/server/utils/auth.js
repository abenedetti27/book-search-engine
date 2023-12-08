const jwt = require('jsonwebtoken');
const { AuthenticationError } = require('apollo-server-express');
const secret = 'mysecretsshhhhh';
const expiration = '2h';

module.exports = {
  authMiddleware: function ({ req }) {
    let token = req.headers.authorization || '';

    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    if (!token) {
      return { user: null };
    }

    try {
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      return { user: data };
    } catch (err) {
      console.error('Invalid token', err);
      throw new AuthenticationError('Invalid token');
    }
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};
