const express = require("express");
const router = express.Router();
const {
  register,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  userDetails,
  profileUpdate,
  getAllUsers,
  getUser,
  updateUserRole,
  deleteUser,
  //users
  addUser,
  getUserByGymid,
  SetAttendance,
  updateUsersSub,

  //gym-admin
  GetAllDetails,
} = require("../controllers/userController");

const { isAuthorized, roleAuthorize } = require("../middleware/auth");

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/forgotpassword").post(forgotPassword);
router.route("/resetpassword/:id").post(resetPassword);
router.route("/me").get(isAuthorized, userDetails);
router.route("/password/update").put(isAuthorized, updatePassword);
router.route("/me/profileupdate").put(isAuthorized, profileUpdate);
router
  .route("/user/adduser")
  .post(isAuthorized, roleAuthorize(["Gym"]), addUser);
router
  .route("/user/getgymuser/:gymid")
  .get(isAuthorized, roleAuthorize(["Gym"]), getUserByGymid)
  .put(isAuthorized, roleAuthorize(["Gym"]), SetAttendance);
router
  .route("/user/updateuser/")
  .put(isAuthorized, roleAuthorize(["Gym"]), updateUsersSub);
router.route("/gym-admin").post(isAuthorized, GetAllDetails);
router
  .route("/admin/getallusers")
  .get(isAuthorized, roleAuthorize("admin"), getAllUsers);
router
  .route("/admin/user/:id")
  .get(isAuthorized, roleAuthorize("admin"), getUser)
  .put(isAuthorized, roleAuthorize("admin"), updateUserRole)
  .delete(isAuthorized, roleAuthorize("admin"), deleteUser);

module.exports = router;
