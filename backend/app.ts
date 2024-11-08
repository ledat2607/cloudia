import express, { NextFunction, Request, Response } from "express"
export const app = express();


//import router

//Import libary
import cors from "cors"
import cookieParser from "cookie-parser";


//Middlewarr
import { ErrorMiddleWare } from "./middleware/error";
import userRoute from "./routes/user-routes";

//body parser
app.use(express.json({ limit: "50mb" }));


//cookie parser
app.use(cookieParser())

//cors => cross origin resource sharing
app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);

//user api
app.use("/api/v1/user", userRoute);


//unknow route
app.all("*", (req,res,next)=>{
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    err.statusCode = 404
    next(err);
})


app.use(ErrorMiddleWare);