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
  sendResetPasswordEmail,
  createHash,
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

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new CustomError.BadRequestError('Please provide a valid email');
  }

  const user = await User.findOne({ email });

  // Here is something interesting:
  // We don't check if user DOES NOT EXIST and throw an error here.
  // At the end of "forgotPassword" handler execution
  // we send back the response with status code 200 and success message (even if there's no user).
  // Why? Because if our app is attacked by some hacker, we do not want to give him a clue
  // on whether the email is really in the DB or not so that he can keep guessing emails.
  // 1) If the real registered user makes such a request then he will have no problems checking
  // his email and find the link there.
  // 2) In case of attacker doing the same thing, he will also get success response, then
  // will try to check the email, and he won't find anything there! Which can throw him off
  // and result in him making guesses on what is going on. And as a result
  // this can make our app a little more secure.

  // In reality, we are of course depending on user document from the DB:
  if (user) {
    // if there's a user in the DB, we want to create a passwordToken
    const passwordToken = crypto.randomBytes(70).toString('hex');
    // send email with reset link
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      passwordToken,
      origin: 'http://localhost:3000',
    });
    // set expiration time for passwordToken:
    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    // add token and expiration time to user document:
    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' });
};

const resetPassword = async (req, res) => {
  // reset password functionality is set up on the FE such that FE sends
  // a request with email, token, password in the body:
  const { email, token, password } = req.body;

  if (!email || !token || !password) {
    throw new CustomError.BadRequestError(
      'Please provide email, token, password',
    );
  }

  const user = await User.findOne({ email });
  // and once again we will not throw an error if user does not exist
  // because we want to make app attackers' life difficult
  if (user) {
    const currentDate = new Date();

    // when we found the user document in the DB, we want to check if passwordToken is
    // correct and not expired:
    if (
      user.passwordToken === createHash(token)
      && user.passwordTokenExpirationDate > currentDate
    ) {
      // and if so then apply the changes:
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' });
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
