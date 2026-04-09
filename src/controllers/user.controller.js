import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uplodaOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = User.findById(userId)
    const accessToken = user.generateAcceessToken()
    const refreshToken = user.generateRefreshToken()

    user.refreshToken = refreshToken
    await user.save({ validateBeforeSave: false })

    return { accessToken, refreshToken }

  } catch (error) {
    throw new ApiError(500, "Something went wrong while generating refresh and access token")
  }
}

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

  // user or email
  if (!username || !email) {
    throw new ApiError(400, "username or password is required!")
  }

  // find the user
  const user = await User.findOne({
    $or: [{ username }, { email }]
  })

  if (!user) {
    throw new ApiError(404, "User does not exist!")
  }

  // password check 
  // we will not use User, because it is mongoDB's object but our user object is user.
  const isPasswordValid = await user.isPasswordCorrect(password)

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials!")
  }

  // access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

  // send cookie
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
    httpOnly: true,
    secure: true
    // those cookie now only modifiable by server
  }

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200, {
        user: loggedInUser, accessToken, refreshToken
        // we are giving the option to user, it can store refresh and access token by it self. Ex - localStorage
      },
        "User logged in succeessfully!"
      )
    )
});

const logoutUser = asyncHandler(async (req, res) => {
  
})

export { registerUser, loginUser };
