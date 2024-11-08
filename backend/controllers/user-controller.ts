import { Request, Response, NextFunction } from "express";
import userModel, { IUser } from "../model/user-model";
import ErrorHandle from "../utils/ErrorHandle";
import { CatchAsyncError } from "../middleware/catchAsyncError";
import jwt, { Secret } from "jsonwebtoken";
import ejs from "ejs";
import path from "path";

import {
  accessTokenOptions,
  refreshTokenOptions,
  sendToken,
} from "../utils/jwt";

import cloudinary from "cloudinary";
import sendMail from "../utils/sendMail";

require("dotenv").config();


//register new user
interface IRegistionBody {
  name: string;
  email: string;
  password: string;
  avatar?: string;
}
export const register = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const { name, email, password } = req.body;

    try {
      const isUser = await userModel.findOne({ email });
      if (isUser) {
        return next(
          new ErrorHandle("Email is exists. Please another email !", 400)
        );
      }
      const user: IRegistionBody = {
        name,
        email,
        password,
      };
      const activationToken = createActivationToken(user);
      const activationCode = activationToken.activationCode;
      const data = {
        user: {
          name: user.name,
        },
        activationCode,
      };
      const html = await ejs.renderFile(
        path.join(__dirname, "../mail/activ-mail.ejs"),
        data
      );
      try {
        await sendMail({
          email: user.email,
          subject: "Active your account",
          template: "activ-mail.ejs",
          data,
        });
        res.status(200).json({
          success: true,
          message: `Please check ${user.email} to active your email !`,
          activationToken: activationToken.token,
          activationCode,
        });
      } catch (error: any) {
        return next(new ErrorHandle(error.message, 404));
      }
    } catch (error) {
      return next(new ErrorHandle("Error!", 404));
    }
  }
);

//create activationToken
interface IActivationToken {
  token: string;
  activationCode: string;
}
export const createActivationToken = (user: any): IActivationToken => {
  const activationCode = Math.floor(1000 + Math.random() * 9000).toString();
  const token = jwt.sign(
    {
      user,
      activationCode,
    },
    process.env.JWT_SECRET as Secret,
    {
      expiresIn: "5m",
    }
  );
  return { token, activationCode };
};

//activatie user
interface IActivationRequest {
  activation_token: string;
  activation_code: string;
}
export const activationUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { activation_code, activation_token } =
        req.body as IActivationRequest;

      const newUser: { user: IUser; activationCode: string } = jwt.verify(
        activation_token,
        process.env.JWT_SECRET as string
      ) as { user: IUser; activationCode: string };
      if (newUser.activationCode !== activation_code) {
        return next(new ErrorHandle("Invalid code", 404));
      }
      const { name, email, password } = newUser.user;
      const exists = await userModel.findOne({ email });
      if (exists) {
        return next(new ErrorHandle("User already exists !", 404));
      }
      const user = await userModel.create({
        name,
        email,
        password,
        avatar: {
          public_id:
            "https://i.pinimg.com/736x/3f/94/70/3f9470b34a8e3f526dbdb022f9f19cf7.jpg",
          url: "https://i.pinimg.com/736x/3f/94/70/3f9470b34a8e3f526dbdb022f9f19cf7.jpg",
        },
      });
      res.status(200).json({
        success: true,
        message: "New user created !!!",
        activation_token,
        user,
      });
    } catch (error: any) {
      return next(new ErrorHandle(error.message, 404));
    }
  }
);


//login user
interface ILoginRequest {
  email: string;
  password: string;
  isSave: boolean;
}
export const login = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password, isSave } = req.body as ILoginRequest;
      if (!email || !password) {
        return next(new ErrorHandle("Please enter your email & password", 404));
      }
      const user = await userModel.findOne({ email }).select("+password");
      if (!user) {
        return next(
          new ErrorHandle("No accounts found with this email !", 401)
        );
      }
      const isPasswordCompare = await user.comparePassword(password);
      if (!isPasswordCompare) {
        return next(new ErrorHandle("Invalid password !", 402));
      }
      sendToken(user, 200, res, isSave);
    } catch (error: any) {
      return next(new ErrorHandle(error.message, 404));
    }
  }
);

//logout user
export const LogoutUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.cookie("access_token", "", { maxAge: 1 });
      res.cookie("refresh_token", "", { maxAge: 1 });
      res.status(200).json({
        success: true,
        message: "Logout successfull !",
      });
    } catch (error: any) {
      return next(new ErrorHandle(error.message, 404));
    }
  }
);

//get user-infomation
export const getInformation = CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const userId = (req as any).user._id || "";
    const user = await userModel.findById(userId);
    if (!user) {
      return next(new ErrorHandle("User not found", 401));
    }
    res.status(200).json({
      user,
    });
  } catch (error:any) {
    return next(new ErrorHandle(error.message, 404));
  }
})

//update avatar
export const update_avatar=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const userId = (req as any).user._id;
    const { avatar } = req.body;
    const user = await userModel.findById(userId);

    if(!user){
      return next(new ErrorHandle("User not found", 401));
    }
    if(!avatar){
      return next(new ErrorHandle("Can't find any avatar to update", 402));
    }
    if(avatar && user){
      if(user?.avatar.public_id){
        await cloudinary.v2.uploader.destroy(user?.avatar.public_id);
      }
      const myUpload = await cloudinary.v2.uploader.upload(avatar, {
        folder: "cloudia_user_avatar",
        withd: 150,
      });
      user.avatar = {
        public_id: myUpload.public_id,
        url: myUpload.secure_url,
      };
      await user?.save();
    }
    res.status(200).json({
      success: true,
      message: "Update successfull !",
    });
  } catch (error:any) {
    return next(new ErrorHandle(error.message, 404));
  }
})



//generate verify code
export const sendPasswordUpdateCode = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = (req as any).user._id;

    const user = await userModel.findOne(userId);
    if (!user) {
      return next(new ErrorHandle("User not found with this email", 404));
    }

    // Generate a 6-digit verification code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    user.passwordResetCode = verificationCode;
    user.passwordResetExpiry = Date.now() + 10 * 60 * 1000; 
    await user.save();

    const data = {
      user: { name: user.name },
      verificationCode,
    };
    const html = await ejs.renderFile(
      path.join(__dirname, "../mail/verify-update.ejs"),
      data
    );

    try {
      await sendMail({
        email: user.email,
        subject: "Active your account",
        template: "verify-update.ejs",
        data,
      });
      res.status(200).json({
        success: true,
        message: `Please check ${user.email} to active your email !`,
      });
    } catch (error: any) {
      return next(new ErrorHandle(error.message, 404));
    }
    res.status(200).json({
      success: true,
      message: `Verification code sent to ${user.email}`,
    });
  } catch (error: any) {
    return next(new ErrorHandle(error.message, 500));
  }
};

//update password
export const updatePasswordWithCode = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { verificationCode, newPassword, oldPassword } = req.body;
    const userId = (req as any).user._id;

    // Find the user by ID
    const user = await userModel.findById(userId).select("+password");
    if (!user) {
      return next(new ErrorHandle("User not found with this email", 404));
    }

    // Compare old password with the stored one
    const isCompare = await user.comparePassword(oldPassword);
    if (!isCompare) {
      return next(new ErrorHandle("Password doesn't match", 401));
    }

    // Verify the verification code and expiry
    if (
      !user.passwordResetCode ||
      user.passwordResetCode !== verificationCode ||
      typeof user.passwordResetExpiry !== "number" ||
      user.passwordResetExpiry < Date.now()
    ) {
      return next(new ErrorHandle("Invalid or expired verification code", 400));
    }

    user.password = newPassword;

    user.passwordResetCode = "";
    user.passwordResetExpiry = 0;

    await user.save();

    // Send success response
    res.status(200).json({
      success: true,
      message: "Password has been updated successfully",
    });
  } catch (error: any) {
    return next(new ErrorHandle(error.message, 500));
  }
};






