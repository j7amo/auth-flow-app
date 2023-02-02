const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async ({
  name,
  email,
  passwordToken,
  origin,
}) => {
  const resetPasswordURl = `${origin}/user/reset-password?token=${passwordToken}&email=${email}`;
  const message = `<p>Please, reset your password <a href='${resetPasswordURl}'>here</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Password reset',
    html: `<h4>Hello, ${name}</h4>${message}`,
  });
};

module.exports = sendResetPasswordEmail;
