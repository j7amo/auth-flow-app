const CustomError = require('../errors');
const { isTokenValid, attachCookiesToResponse } = require('../utils');
const Token = require('../models/Token');

const authenticateUser = async (req, res, next) => {
  // now we have 2 different tokens, and we want to check them
  const { refreshToken, accessToken } = req.signedCookies;

  try {
    // first we check accessToken because it is our main token for protected resources
    if (accessToken) {
      // if it is present and valid
      const payload = isTokenValid(accessToken);
      // then we just attach the payload extracted from verification
      // process(returned from isTokenValid)
      // to "req.user"(that's one of the main purposes of auth middleware)
      req.user = payload.user;
      // and go to next middleware in chain
      return next();
    }

    // if accessToken has expired(basically we are talking about cookie expiration
    // because we don't set expiration on the token itself) then we check for refreshToken:
    if (refreshToken) {
      const payload = isTokenValid(refreshToken);
      const existingToken = await Token.findOne({
        user: payload.user.userId,
        refreshToken: payload.refreshToken,
      });

      if (!existingToken || !existingToken?.isValid) {
        throw new CustomError.UnauthenticatedError('Authentication Invalid');
      }
      // if refreshToken passed all checks then we want to attach cookies
      // with accessToken and refreshToken to response
      attachCookiesToResponse({
        res,
        user: payload.user,
        refreshTokenString: existingToken.refreshToken,
      });
      req.user = payload.user;
      return next();
    }

    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  } catch (error) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  }
};

const authorizePermissions = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    throw new CustomError.UnauthorizedError(
      'Unauthorized to access this route',
    );
  }
  next();
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};
