import nodemailer, { Transporter } from "nodemailer";
require("dotenv").config();
import ejs from "ejs";
import path from "path";

interface EmailOptions {
  email: string;
  subject: string;
  template: string;
  data: { [key: string]: any };
}

const sendMail = async (option: EmailOptions): Promise<void> => {
  const transporter: Transporter = nodemailer.createTransport({
    host: process.env.SMPT_HOST,
    port: parseInt(process.env.SMPT_PORT || "587"),
    service: process.env.SMPT_SERVICE,
    auth: {
      user: process.env.SMPT_MAIL,
      pass: process.env.SMPT_PASSWORD,
    },
  });

  const { email, subject, template, data } = option;
  const templatePath = path.join(__dirname, "../mail", template);
  const html: string = await ejs.renderFile(templatePath, data);

  // Fix typo from mailOptios to mailOptions
  const mailOptions = {
    from: process.env.SMPT_MAIL,
    to: email,
    subject,
    html,
  };

  // Send the email
  await transporter.sendMail(mailOptions);
};

export default sendMail;
