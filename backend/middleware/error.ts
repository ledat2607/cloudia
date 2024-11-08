import { NextFunction, Request, Response } from "express";
import ErrorHandle from "../utils/ErrorHandle";


export const ErrorMiddleWare = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  err.statusCode = err.statusCode || 500;
  err.messsage = err.messsage || "Internal Server Error !";

  //wrong mmongoDb
  if (err.name === "CastError") {
    const messsage = `Resource not found. Invalid: ${err.path}`;
    err = new ErrorHandle(messsage, 400);
  }
  //Duplicated value
  if (err.code === 11000) {
    const messsage = `Duplicated ${Object.keys(err.keyValue)}`;
    err = new ErrorHandle(messsage, 401);
  }
  //Wrong json error
  if (err.name === "JsonwebTokenError") {
    const messsage = `JsonwebToken Error`;
    err = new ErrorHandle(messsage, 402);
  }
  //JWt expired
  if (err.name === "TokenExpiredError") {
    const messsage = `JWT have been expired. Please login again !!`;
    err = new ErrorHandle(messsage, 403);
  }
  res.status(err.statusCode).json({
    success: false,
    message: err.message,
  });
};
