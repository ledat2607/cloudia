require("dotenv").config();
import { Response } from "express";
import { IUser } from "../model/user-model";

interface ITokenOptions {
  expires: Date;
  maxAge: number;
  httpOnly: boolean;
  samesite: "lax" | "strict" | "none" | undefined;
  secure?: boolean;
}

// Parse environment variables
const accessTokenExpire = parseInt(process.env.ACCESS_TOKEN_EXPIRE || "300", 10);
const refreshTokenExpire = parseInt(
  process.env.REFRESH_TOKEN_EXPIRE || "1200",
  10
);

// Options for cookies
export const accessTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + accessTokenExpire * 60 * 60 * 1000),
  maxAge: accessTokenExpire * 60 * 60 * 1000,
  httpOnly: true,
  samesite: "lax",
  secure: true,
};

export const refreshTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + refreshTokenExpire * 24 * 60 * 60 * 1000),
  maxAge: refreshTokenExpire * 24 * 60 * 60 * 1000,
  httpOnly: true,
  samesite: "lax",
};

// Send token function
export const sendToken = (user: IUser, statusCode: number, res: Response, isSave: boolean) => {
  const accessToken = user.SignAccessToken();
  const refreshToken = user.SignRefreshToken();

  // Configure access and refresh token expiration based on isSave
  const accessTokenExpireTime = isSave ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30 days or 1 day
  const refreshTokenExpireTime = isSave
    ? 7 * 24 * 60 * 60 * 1000
    : 24 * 60 * 60 * 1000;

  // Clone and modify options based on isSave
  const dynamicAccessTokenOptions: ITokenOptions = {
    ...accessTokenOptions,
    expires: new Date(Date.now() + accessTokenExpireTime),
    maxAge: accessTokenExpireTime,
  };

  const dynamicRefreshTokenOptions: ITokenOptions = {
    ...refreshTokenOptions,
    expires: new Date(Date.now() + refreshTokenExpireTime),
    maxAge: refreshTokenExpireTime,
  };

  // Only set secure cookies in production
  if (process.env.NODE_ENV === "production") {
    dynamicAccessTokenOptions.secure = true;
    dynamicRefreshTokenOptions.secure = true;
  }

  // Set cookies with dynamic options
  res.cookie("access_token", accessToken, dynamicAccessTokenOptions);
  res.cookie("refresh_token", refreshToken, dynamicRefreshTokenOptions);

  res.status(statusCode).json({
    success: true,
    user,
    accessToken,
  });
};

