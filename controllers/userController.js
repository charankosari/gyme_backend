const asyncHandler = require("../middleware/asynchandler");
const errorHandler = require("../utils/errorHandler");
const User = require("../models/userModel");
const sendJwt = require("../utils/jwttokenSend");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");

// user register
exports.register = asyncHandler(async (req, res, next) => {
  const {
    gymname,
    gymemail,
    gymnumber,
    password,
    gymaddress,
    gymsubsription,
    gymlicense,
    gymzone,
    ownernumber,
    owneremail,
    owneraadhar,
    ownerpan,
  } = req.body;

  let gym = await User.findOne({ gymemail });
  let user2 = await User.findOne({ gymnumber });
  if (gym) {
    return next(new errorHandler("gym already exist", 401));
  }
  if (user2) {
    return next(new errorHandler("gym already exist", 401));
  }
  gym = await User.create({
    gymname,
    gymemail,
    gymnumber,
    password,
    gymaddress,
    gymsubsription,
    gymlicense,
    gymzone,
    ownernumber,
    owneremail,
    owneraadhar,
    ownerpan,
  });
  sendJwt(gym, 201, "registerd successfully", res);
});

//user login
exports.login = asyncHandler(async (req, res, next) => {
  const { gymemail, gymnumber, password } = req.body;
  if (!password) {
    return next(new errorHandler("Enter Password", 403));
  }
  if (!gymemail && !gymnumber) {
    return next(new errorHandler("Enter Email or Phone Number", 403));
  }
  let user;
  if (gymemail) {
    user = await User.findOne({ gymemail }).select("+password");
  }
  if (gymnumber && !user) {
    user = await User.findOne({ gymnumber }).select("+password");
  }
  if (!user) {
    return next(
      new errorHandler("Invalid Email/Phone Number or Password", 403)
    );
  }
  const passwordMatch = await user.comparePassword(password);
  if (!passwordMatch) {
    return next(
      new errorHandler("Invalid Email/Phone Number or Password", 403)
    );
  }
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  sendJwt(user, 200, "Login successfully", res);
});

// forgot password
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const gymemail = req.body.gymemail;
  const user = await User.findOne({ gymemail });

  if (!user) {
    return next(new errorHandler("User doesn't exist", 404));
  }
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  const token = user.resetToken();
  const resetUrl = `bookmyappointments://resetpassword?token=${token}`;
  const htmlMessage = `
  <html>
  <body style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #fff; margin: 0; padding: 0; background-color: #000;">
    <div style="max-width: 600px; margin: 40px auto; padding: 20px; background: #1a1a1a; border-radius: 10px; box-shadow: 0 8px 20px rgba(0,0,0,0.3);">
      <div style="text-align: center;">
        <img src="https://agency.trivedagroup.com/static/media/logo.03518202920b9b27869a.png" alt="Gyme Logo" style="width: 100px; border-radius: 50%; margin-bottom: 20px;">
        <h1 style="color: #fff; font-size: 24px; margin-bottom: 10px;">Gyme</h1>
      </div>
      <h2 style="color: #fff; font-size: 22px; text-align: center; margin-bottom: 20px;">Password Reset Request</h2>
      <p style="font-size: 16px; line-height: 1.5; color: #fff;">Dear User,</p>
      <p style="font-size: 16px; line-height: 1.5; color: #fff;">We received a request to reset your password. You can reset your password by clicking the button below:</p>
      <p style="text-align: center; margin: 30px 0;">
        <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; color: #000; background: #fff; text-decoration: none; border-radius: 30px; font-size: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); transition: background 0.3s ease;">
          Reset Password
        </a>
      </p>
      <p style="font-size: 16px; line-height: 1.5; color: #fff;">If you did not request this, please ignore this email. Your password will remain unchanged.</p>
      <p style="font-size: 16px; line-height: 1.5; color: #fff;">Thank you,<br>The Gyme Team</p>
      <hr style="border: 0; border-top: 1px solid #444; margin: 20px 0;">
      <p style="font-size: 14px; color: #aaa; text-align: center;">&copy; 2024 Gyme. All rights reserved.</p>
    </div>
  </body>
</html>
  `;

  await user.save({ validateBeforeSave: false });

  try {
    const mailMessage = await sendEmail({
      email: user.gymemail,
      subject: "Password Reset",
      html: htmlMessage,
    });

    res.status(200).json({
      success: true,
      message: "Mail sent successfully",
      mailMessage: mailMessage,
    });
  } catch (e) {
    user.resetPasswordExpire = undefined;
    user.resetPasswordToken = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new errorHandler(e.message, 500)); // Use 500 for server errors
  }
});

// reset password
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const token = req.params.id;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() },
  });
  if (!user) {
    return next(new errorHandler("Reset password is invalid or expired", 400));
  }
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  if (req.body.password != req.body.confirmPassword) {
    return next(new errorHandler("Password dosnt match", 401));
  }
  user.password = req.body.password;
  user.resetPasswordExpire = undefined;
  user.resetPasswordToken = undefined;
  await user.save();
  sendJwt(user, 201, "reset password successfully", res);
});

// update password
exports.updatePassword = asyncHandler(async (req, res, next) => {
  const { password, oldPassword } = req.body;
  const user = await User.findById(req.gym.id).select("+password");
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  const passwordCheck = await user.comparePassword(oldPassword);
  if (!passwordCheck) {
    return next(new errorHandler("Wrong password", 400));
  }

  user.password = password;
  await user.save();
  sendJwt(user, 201, "password updated successfully", res);
});

// my details
exports.userDetails = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.gym.id);
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  if (!user) {
    return next(new errorHandler("Login to access this resource", 400));
  }
  res.status(200).send({ success: true, user });
});
exports.profileUpdate = asyncHandler(async (req, res, next) => {
  const {
    gymname,
    gymemail,
    gymnumber,
    gymaddress,
    gymzone,
    ownernumber,
    owneremail,
  } = req.body;

  const user = await User.findById(req.gym.id);

  // Check if the user exists
  if (!user) {
    return next(new errorHandler("User not found", 404));
  }
  if (user.gymsubsription === "trial" && user.isTrialExpired()) {
    return next(
      new errorHandler(
        "Your trial period has expired. Please upgrade to a pro subscription.",
        403
      )
    );
  }
  if (gymname) user.gymname = gymname;
  if (gymemail) user.gymemail = gymemail;
  if (gymnumber) user.gymnumber = gymnumber;
  if (gymaddress) user.gymaddress = gymaddress;
  if (gymzone) user.gymzone = gymzone;
  if (ownernumber) user.ownernumber = ownernumber;
  if (owneremail) user.owneremail = owneremail;

  await user.save();

  res.status(200).json({ success: true, user });
});

// get all users---admin
exports.getAllUsers = asyncHandler(async (req, res, next) => {
  const users = await User.find();
  res.status(200).json({ success: true, users });
});

// get single user---admin
exports.getUser = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  res.status(200).json({ success: true, user });
});

// update user role ---admin
exports.updateUserRole = asyncHandler(async (req, res, next) => {
  const id = req.params.id;
  let user = await User.findById(id);
  if (!user) {
    return next(new errorHandler(`user dosent exist with id ${id}`), 400);
  }
  const updatedUserData = {
    role: req.body.role,
  };
  user = await User.findByIdAndUpdate(id, updatedUserData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });
  res.status(201).json({ success: true, user });
});

// delete user --admin
exports.deleteUser = asyncHandler(async (req, res, next) => {
  const id = req.params.id;
  const user = await User.findById(id);
  if (!user) {
    return next(new errorHandler(`user dosent exist with id ${id}`), 400);
  }
  const message = await User.findByIdAndDelete(id);

  res.status(200).json({ success: true, message: "user deleted successfully" });
});
