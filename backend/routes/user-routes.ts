import express from "express"
import {
  register,
  activationUser,
  login,
  LogoutUser,
  getInformation,
  update_avatar,
  sendPasswordUpdateCode,
  updatePasswordWithCode,
} from "../controllers/user-controller";
import { authorizeRoles, isAuthenticated } from "../middleware/auth";
const userRoute = express.Router();

//auth
userRoute.post("/registration", register)
userRoute.post("/active-user", activationUser);
userRoute.post("/login", login);
userRoute.post("/sign-out", LogoutUser);

///profile
userRoute.get("/get-infomation", isAuthenticated, getInformation);
userRoute.put("/update-avatar", isAuthenticated, update_avatar);
userRoute.post("/send-password-update-code",isAuthenticated, sendPasswordUpdateCode);
userRoute.post("/update-password", isAuthenticated, updatePasswordWithCode);

export default userRoute;