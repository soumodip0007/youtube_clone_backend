import { Router } from 'express'
import { registerUser, loginUser, logoutUser, refreshAccessToken } from '../controllers/user.controller.js'
import { upload } from '../middlewares/multer.middleware.js'
import { verifyJWT } from '../middlewares/auth.middleware.js'

const router = Router()

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)

// secured route
// before run logoutUser we will run verifyJWT method, that's why we have written next() at the end the the method body of verifyJWT, because our router may get confused which method to execute, So we call the method verifyJWT first then inside it next() has written so after execution of the method verifyJWT it will execute logoutUser
router.route("/logout").post(verifyJWT, logoutUser)

router.route("/refresh-token").post(refreshAccessToken)

export default router