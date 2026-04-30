import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uplodaOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  const { fullName, email, username, password } = req.body;

  // validation - not empty
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // check if user already exists: username, email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  console.log(req.files);
  //     [{
  //       fieldname: "avatar",
  //       originalname: "student.png",
  //       encoding: "7bit",
  //       mimetype: "image/png",
  //       destination: "./public/temp",
  //       filename: "student.png",
  //       path: "public\\temp\\student.png",
  //       size: 5049,
  //     }
  //   ],
  //     [
  //       {
  //         fieldname: "coverImage",
  //         originalname: "aiCloudConceptWithRobotArms.png",
  //         encoding: "7bit",
  //         mimetype: "image/png",
  //         destination: "./public/temp",
  //         filename: "aiCloudConceptWithRobotArms.png",
  //         path: "public\\temp\\aiCloudConceptWithRobotArms.png",
  //         size: 107905,
  //       },
  //     ]);

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // check for images, check for avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // upload them in cloudinary
  const avatar = await uplodaOnCloudinary(avatarLocalPath);
  const coverImage = await uplodaOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // create user object - create entry in db
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "", // if coverImage uploaded then provide the url otherwise provide empty string
    email,
    password,
    username: username.toLowerCase(),
  });

  // remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // check for user creation
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // return res
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  // req body -> data
  const { email, username, password } = req.body;

  // username or email
  if (!username && !email) {
    throw new ApiError(400, "username or password is required!");
  }

  // if (!(username || email)) {
  //   throw new ApiError(400, "username or password is required!");
  // }

  // find the user
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not exist!");
  }

  // password check
  // we will not use User, because it is mongoDB's object but our user object is user.
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials!");
  }

  // access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  // send cookie
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
    // those cookie now only modifiable by server we cannot modify it from frontend
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
          // we are giving the option to user, it can store refresh and access token by it self. Ex - localStorage
        },
        "User logged in successfully!"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    // for this in the return response we will get new updated value
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out!"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  // Get refresh token from cookies or request body
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  // If no token is provided then throw unauthorized
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request!");
  }

  try {
    // Verify the refresh token using JWT secret
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // Find user using ID stored inside token
    const user = await User.findById(decodedToken?._id);

    // If user does not exist throw invalid token
    if (!user) {
      throw new ApiError(401, "Invalid refresh token!");
    }

    // Check if token matches the one stored in DB
    // Prevents reuse or token theft
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used!");
    }

    const options = {
      httpOnly: true, // prevents access via JS (XSS protection)
      secure: true, // only sent over HTTPS
    };

    // Generate new access and refresh tokens
    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    // Send new tokens in cookies with response
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed!"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token!");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully!"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully!"));
});

const updateAccoundDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  if (!fullName || !email) {
    throw new ApiError(400, "All fields are required!");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName: fullName,
        email: email,
      },
    },
    // After updation the information will be returned here
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully!"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing!");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);

  if (!avatar?.url) {
    throw new ApiError(400, "Error while uploading on avatar!");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar updated successfully!"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;

  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image file is missing!");
  }

  const coverImage = await uplodaOnCloudinary(coverImageLocalPath);

  if (!coverImage.url) {
    throw new ApiError(400, "Error while uploading on cover image!");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, "Cover image updated successfully!"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;

  if (!username?.trim()) {
    throw new ApiError(400, "username is missing!");
  }

  const channel = await User.aggregate([
    // Stage 1: Match the user based on username
    {
      $match: {
        username: username?.toLowerCase(), // Convert input username to lowercase and find matching user
      },
    },

    // Stage 2: Lookup subscribers (people who subscribed to this channel)
    {
      $lookup: {
        from: "subscriptions", // Collection name where subscription data is stored
        localField: "_id", // Current user's _id (channel id)
        foreignField: "channel", // Match where channel field equals this user's _id
        as: "subscribers", // Store result in 'subscribers' array
      },
    },

    // Stage 3: Lookup channels that this user has subscribed to
    {
      $lookup: {
        from: "subscriptions", // Same collection
        localField: "_id", // Current user's _id
        foreignField: "subscriber", // Match where subscriber field equals this user's _id
        as: "subscribedTo", // Store result in 'subscribedTo' array
      },
    },

    // Stage 4: Add computed fields
    {
      $addFields: {
        // Count total subscribers
        subscribersCount: {
          $size: "$subscribers", // Get length of subscribers array
        },

        // Count how many channels this user has subscribed to
        channelsSubscriberdToCount: {
          $size: "$subscribedTo", // Get length of subscribedTo array
        },

        // Check if current logged-in user is subscribed to this channel
        isSubscribed: {
          $cond: {
            if: {
              $in: [
                req.user?._id, // Current logged-in user's ID
                "$subscribers.subscriber", // Array of subscriber IDs from subscribers list
              ],
            },
            then: true, // If found, user is subscribed
            else: false, // Otherwise, not subscribed
          },
        },
      },
    },

    // Stage 5: Project only required fields
    {
      $project: {
        fullName: 1, // Include full name
        username: 1, // Include username
        subscribersCount: 1, // Include subscribers count
        channelsSubscriberdToCount: 1, // Include subscribed channels count
        avatar: 1, // Include avatar image
        coverImage: 1, // Include cover image
        email: 1, // Include email
      },
    },
  ]);

  if (!channel?.length) {
    throw new ApiError(404, "channel does not exists!");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, channel[0], "User channel fetched successfully!")
    );
});

const getWatchHistory = asyncHandler(async (req, res) => {
  const user = await User.aggregate([
    // 1. Match the logged-in user
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id),
        // WHY:
        // - MongoDB stores _id as ObjectId
        // - req.user._id usually comes as string (from JWT/session)
        // - So we convert string → ObjectId for exact match
      },
    },

    // 2. Populate watchHistory (array of video IDs → actual video documents)
    {
      $lookup: {
        from: "videos", // Target collection (videos)
        localField: "watchHistory", // Field in User (array of video IDs)
        foreignField: "_id", // Match with Video _id
        as: "watchHistory", // Replace IDs with full video objects

        // Nested pipeline for each video
        pipeline: [
          // 3. Populate owner of each video
          {
            $lookup: {
              from: "users", // Owner is stored in users collection
              localField: "owner", // Field in video (owner ID)
              foreignField: "_id", // Match with user _id
              as: "owner", // Result will be array

              // Only fetch required owner fields
              pipeline: [
                {
                  $project: {
                    fullName: 1,
                    username: 1,
                    avatar: 1,
                  },
                  // WHY:
                  // - Reduce payload size
                  // - Improve performance
                  // - Avoid exposing sensitive fields (email, password, etc.)
                },
              ],
            },
          },

          // 4. Convert owner array → single object
          {
            $addFields: {
              owner: {
                $first: "$owner",
              },
            },
            // WHY:
            // - $lookup always returns an array
            // - But each video has only ONE owner
            // - So we extract the first element to simplify structure
          },
        ],
      },
    },
  ]);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        user[0].watchHistory,
        "Watch history fetched successfully!"
      )
    );
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccoundDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory,
};
