import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

// It will verify that does the user exists or not
// custom middleware
// asyncHandler(async (req, _, next) - instead of passing the res we are passing _ because res is not used anywhere.
export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    // extracting the token by using cookies or Authorization Bearer - If we get Bearer and then space then we should remove with empty string
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      throw new ApiError(401, "Unauthorized request!");
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "Invalid Access Token!");
    }

    // we are adding new object(user) to the req
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid Access Token!");
  }
});
