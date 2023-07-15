const jwt = require('jsonwebtoken');

const { JWT_SECRET } = process.env;

const extractToken = (bearerToken) => bearerToken.split(' ')[1];

module.exports = (req, res, next) => {
  const bearerToken = req.header('Authorization');
  
  if (!bearerToken) {
    const err = new Error('Token not found');
    err.statusCode = 401;
    return next(err);
  }

  const token = extractToken(bearerToken);

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    req.user = payload;

    return next();
  } catch (err) {
    err.statusCode = 401;

    return next(err);
  }
};