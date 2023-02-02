/* eslint-disable no-underscore-dangle */
const crypto = require('crypto');
const { StatusCodes } = require('http-status-codes');
const User = require('../models/User');
const Token = require('../models/Token');
const CustomError = require('../errors');
const {
  attachCookiesToResponse,
  createTokenUser,
  sendVerificationEmail,
} = require('../utils');

// We are going to change the AUTH FLOW.
// It will look like this
// 1) When user has registered (we created a new User document with
// randomly generated "verificationToken" field and "isVerified" field set to "false" by default),
// we will send a verification email with a link inside.
// 2) User clicks the link and frontend makes a request to the server
// WITH VERIFICATION TOKEN.
// 3) Server checks if user exists and tokens match, and updates User document in the DB
// with data about successful verification.
// 4) When user is trying to log in, server will check whether user is verified.
// 5) If user is verified, server will create an access token and send it back via cookies.
const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  // here we set up verification token that will be sent along with verification email
  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    name,
    email,
    password,
    role,
    // when we create the User document, we now also store the verification token in the DB
    verificationToken,
  });

  // We don't need these lines here in our new auth flow, because
  // we don't set the cookies at this point yet. Why? The user must first
  // verify the email.
  // const tokenUser = createTokenUser(user);
  // attachCookiesToResponse({ res, user: tokenUser });
  // res.status(StatusCodes.CREATED).json({ user: tokenUser });

  // now we send email with the token
  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin: 'http://localhost:3000',
  });

  res.status(StatusCodes.CREATED).json({
    msg: 'Success! Please check your email to verify account',
  });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;

  if (!verificationToken || !email) {
    throw new CustomError.UnauthenticatedError('Invalid credentials');
  }

  // find the user by email (we can use it instead of ID because emails are unique)
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Verification failed');
  }

  // we check if stored and received verification tokens match
  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification failed');
  }

  // if tokens match, then we set fields:
  user.isVerified = true;
  user.verified = new Date(Date.now());
  // we clear verification token because we don't want our users
  // to verify their email multiple times, so that if user tries
  // for whatever reason to verify again - he will fail because tokens
  // will no longer match:
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email verified!' });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  // here we want to check if user has verified his email, because
  // there can be a situation when user does not verify it and tries to log in,
  // and we do not want to allow this flow:
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Please verify your email');
  }

  // and only after successful email verification we create access token,
  // put it into cookie and send it back to the user for storing in the browser:
  const tokenUser = createTokenUser(user);

  // We want to create REFRESH token that will be used for refreshing access token.
  // Why do we need a REFRESH TOKEN? For security reasons! With the help of it
  // we can re-issue a short-term ACCESS TOKEN e.g. every 15 minutes. So that
  // if it is somehow leaked it will expire shortly. And REFRESH token helps
  // us set this flow securely and seamlessly (user doesn't even have to enter
  // credentials every 15 minutes).
  let refreshToken = '';
  // before creating a new refresh token we should check if the user already
  // has one active in the DB and use it instead:
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    const { isValid } = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    refreshToken = existingToken;
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });
    res.status(StatusCodes.OK).json({ user: tokenUser });

    return;
  }
  // If there's no refreshToken in the DB for the current user
  // then we go the full cycle of token creation:
  // To create REFRESH token we need to get all the needed data for the Token model:
  refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent']; // OR req.get('user-agent');
  const { ip } = req;
  const userToken = {
    refreshToken,
    userAgent,
    ip,
    user: user._id,
  };

  // and create the token in the DB
  await Token.create(userToken);
  // Then we want to check for existing access token

  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
};
