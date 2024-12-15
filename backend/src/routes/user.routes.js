import { loginUser, logoutUser, registerUser } from "../controllers/user.controllers"
import {Router} from express
import { verifyJWT } from "../middlewares/auth.middleware"

const router=Router()

router.route("/register").post(registerUser)

router.route("/logout").post(verifyJWT,logoutUser)

router.route("/login").post(loginUser)