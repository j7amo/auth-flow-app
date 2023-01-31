const sendEmail = require('./sendEmail');

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  // To construct a link that we'll send to the user, we need:
  // - origin;
  // - verificationToken;
  // - email.
  // Keep in mind that we also need to create the corresponding route on the FE, because
  // user cannot click the link and magically go directly to the server.
  // Instead, the flow is the following:
  //
  // 1) User clicks the link.
  // 2) Browser loads FE app.
  // 3) '/user/verify-email' route is matched
  // 4) FE app constructs a new request and sends it to th server:
  // await axios.post('/api/v1/auth/verify-email', {
  //         verificationToken: query.get('token'),
  //         email: query.get('email'),
  //       });
  // 5) Server checks if everything is OK (verificationToken, email), updates
  // User document (sets it to verified state) and sends back to FE the success status response.
  // 6) FE shows the success page to the user with the link to "Login" page.
  // 7) User can now use his creds to log in.
  const verifyEmailURl = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;
  const message = `<p>Confirm email: <a href='${verifyEmailURl}'>Verify your email here</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Confirm your email!',
    html: `<h4>Hello, ${name}</h4>${message}`,
  });
};

module.exports = sendVerificationEmail;
