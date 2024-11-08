import { app } from "./app";

require("dotenv").config();

import connectDB from "./db/connect";

import {v2 as cloudinary} from "cloudinary"


cloudinary.config({
  cloud_name: process.env.CLOUDARY_NAME,
  api_key: process.env.CLOUDARY_API_KEY,
  api_secret: process.env.CLOUDARY_SECRET,
});
//create server
app.listen(process.env.PORT, () => {
  console.log(`Server running at PORT: ${process.env.PORT}`);
});


connectDB();