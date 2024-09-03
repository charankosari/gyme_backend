const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const errorHandler = require("../utils/errorHandler");
const asyncHandler = require("../middleware/asynchandler");

exports.isAuthorized = asyncHandler(async (req, res, next) => {
  const headers = req.headers["authorization"];
  if (!headers) {
    return next(new errorHandler("no jwtToken provided unauthorised ", 401));
  }
  const jwtToken = headers.split(" ")[1];
  if (!jwtToken) {
    return next(new errorHandler("login to access this resource", 401));
  }
  const { id } = jwt.verify(jwtToken, process.env.jwt_secret);
  const user = await User.findById(id);
  req.gym = user;
  next();
});

exports.roleAuthorize = (roles) => {
  return (req, res, next) => {
    const userRole = req.gym?.role; // Access role from req.user

    if (!userRole) {
      return next(new errorHandler("User role is not set.", 401));
    }

    if (!roles.includes(userRole)) {
      return next(
        new errorHandler(
          `The role ${userRole} is not allowed to access this resource.`,
          401
        )
      );
    }

    next();
  };
};
