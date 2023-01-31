// eslint-disable-next-line import/no-extraneous-dependencies
const nodemailer = require('nodemailer');
const transporterConfig = require('./nodeMailerConfig');

const sendEmail = async ({ to, subject, html }) => {
  // Generate test SMTP service account from ethereal.email
  // Only needed if you don't have a real mail account for testing
  // const testAccount = await nodemailer.createTestAccount();

  // create reusable transporter object using the default SMTP transport
  const transporter = nodemailer.createTransport(transporterConfig);

  // send mail with defined transport object
  await transporter.sendMail({
    from: '"Verification Service" <verification@service.com>', // sender address
    to, // list of receivers
    subject, // Subject line
    html, // html body
  });
};

module.exports = sendEmail;
