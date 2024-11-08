import { Response, Request, NextFunction } from "express";
import ErrorHandle from "../utils/ErrorHandle";
import jwt, { JwtPayload } from "jsonwebtoken";
import { CatchAsyncError } from "./catchAsyncError";
import userModel from "../model/user-model";

export const isAuthenticated = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const access_token = req.cookies.access_token as string;
    if (!access_token) {
      return next(new ErrorHandle("Please login to access !!", 404));
    }

    // Xác thực token
    const decoded = jwt.verify(
      access_token,
      process.env.ACCESS_TOKEN as string
    ) as JwtPayload;
    if (!decoded) {
      return next(new ErrorHandle("Access token is invalid", 404));
    }

    // Thay thế Redis bằng truy vấn cơ sở dữ liệu
    const user = await userModel.findById(decoded.id); // Giả sử bạn đang sử dụng MongoDB
    if (!user) {
      return next(new ErrorHandle("User not found", 404));
    }

    // Lưu thông tin người dùng vào req
    (req as any).user = user; // Lưu nguyên đối tượng user
    next();
  }
);
// Validate user role
export const authorizeRoles = (...roles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!roles.includes((req as any).user.role || "")) {
        return next(
          new ErrorHandle(
            `Role ${(req as any).user.role} is not allowed to access this resource`,
            404
          )
        );
      }
      next();
    };
  };
  