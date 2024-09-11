const asyncHandler = require("../middleware/asynchandler");
const errorHandler = require("../utils/errorHandler");
const User = require("../models/userModel");
const sendJwt = require("../utils/jwttokenSend");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const GymUsersModel = require("../models/GymusersModel");

const moment = require("moment");
const { error } = require("console");
const GymusersModel = require("../models/GymusersModel");

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
function generateGymId() {
  const timestampPart = Date.now().toString().slice(-3);
  const randomPart = Math.floor(100 + Math.random() * 900).toString();

  return timestampPart + randomPart;
}

exports.addUser = asyncHandler(async (req, res, next) => {
  try {
    const {
      name,
      email,
      number,
      gender,
      height,
      weight,
      subendsin,
      subscriptionStartDate,
    } = req.body;
    const gymid = await generateGymId();
    const gid = req.gym.id;
    const subscriptionStartDateMoment = subscriptionStartDate
      ? moment(subscriptionStartDate)
      : moment();

    const subscriptionEndDateMoment = subscriptionStartDateMoment
      .clone()
      .add(subendsin, "days");

    let attendance = {};
    for (
      let m = subscriptionStartDateMoment.clone();
      m.isBefore(subscriptionEndDateMoment);
      m.add(1, "days")
    ) {
      attendance[m.format("DD-MM-YYYY")] = null;
    }

    const newUser = await GymUsersModel.create({
      name,
      email,
      number,
      gender,
      height,
      weight,
      gymid: gymid.substring(0, 6),
      subscriptionStartDate: subscriptionStartDateMoment.toDate(),
      subscriptionEndDate: subscriptionEndDateMoment.toDate(),
      subendsin,
      attendance,
    });

    const htmlMessage = `
    <html>
    <head>
      <style>
        body {
          font-family: Arial, sans-serif;
          color: #333;
          line-height: 1.6;
          padding: 20px;
        }
        h1 {
          color: #2BB673;
        }
        p {
          margin: 10px 0;
        }
        .container {
          max-width: 600px;
          margin: auto;
          padding: 20px;
          border: 1px solid #ddd;
          border-radius: 8px;
        }
        .footer {
          margin-top: 20px;
          font-size: 0.9em;
          color: #666;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Welcome to the Gym!</h1>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Gym ID:</strong> ${gymid.substring(0, 6)}</p>
        <p><strong>Subscription Start Date:</strong> ${subscriptionStartDateMoment.format(
          "DD-MM-YYYY"
        )}</p>
        <p><strong>Subscription Duration:</strong> ${subendsin} days</p>
        <p>We are excited to have you as part of our gym community. If you have any questions or need assistance, feel free to reach out to us.</p>
      </div>
      <div class="footer">
        <p>Thank you for choosing our gym.</p>
        <p>If you did not sign up for this service, please ignore this email.</p>
      </div>
    </body>
    </html>
  `;

    await sendEmail({
      email,
      subject: "Welcome to the Gyme",
      html: htmlMessage,
    });
    const user = await User.findById(gid);
    if (user) {
      user.users = [...user.users, parseInt(gymid.substring(0, 6))];
      await user.save();
    }
    res.status(201).json({
      success: true,
      data: newUser,
    });
  } catch (error) {
    next(error);
  }
});

exports.getUserByGymid = asyncHandler(async (req, res, next) => {
  const { gymid } = req.params;
  const user = await GymUsersModel.findOne({ gymid: gymid });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found with this gymid",
    });
  }

  res.status(200).json({ success: true, user });
});

exports.SetAttendance = asyncHandler(async (req, res, next) => {
  try {
    const { gymid } = req.params;
    const { date, attendance } = req.body;
    if (!["yes", "no"].includes(attendance)) {
      return next(
        new errorHandler(
          "Invalid attendance status. Must be 'yes', 'no', or null.",
          400
        )
      );
    }
    const user = await GymUsersModel.findOne({ gymid: gymid });
    if (!user) {
      return next(new errorHandler(`User with ID ${gymid} not found`, 404));
    }
    user.attendance.set(date, attendance);
    await user.save();
    res.status(200).json({
      success: true,
      message: "Attendance updated successfully",
      user,
    });
  } catch (error) {
    next(error);
  }
});
exports.updateUsersSub = asyncHandler(async (req, res, next) => {
  try {
    const { id, days } = req.body;
    const user = await GymUsersModel.findById(id);
    if (!user) {
      return next(new errorHandler(`User with ID ${id} not found`, 404));
    }
    user.subendsin = Math.floor(user.subendsin) + Math.floor(days);
    let currentSubscriptionEndDate = moment(
      user.subscriptionEndDate,
      "YYYY-MM-DD"
    );
    if (!currentSubscriptionEndDate.isValid()) {
      currentSubscriptionEndDate = moment();
    }

    const updatedSubscriptionEndDate = currentSubscriptionEndDate
      .add(days, "days")
      .format("DD-MM-YYYY");
    user.subscriptionEndDate = updatedSubscriptionEndDate;
    const s = user.attendance;
    const lastEntry = Array.from(s.entries()).pop();
    const lastDate = lastEntry ? lastEntry[0] : null;
    if (lastDate) {
      let currentDate = moment(lastDate, "DD-MM-YYYY");
      for (let i = 1; i <= days; i++) {
        currentDate = currentDate.add(1, "days");
        const newDate = currentDate.format("DD-MM-YYYY");

        s.set(newDate, null);
      }
    } else {
      let currentDate = moment();
      for (let i = 1; i <= days; i++) {
        currentDate = currentDate.add(1, "days");
        const newDate = currentDate.format("DD-MM-YYYY");
        s.set(newDate, null);
      }
    }
    await user.save();

    const htmlMessage = `
    <html>
    <head>
      <style>
        body {
          font-family: Arial, sans-serif;
          color: #333;
          line-height: 1.6;
          padding: 20px;
        }
        h1 {
          color: #2BB673;
        }
        p {
          margin: 10px 0;
        }
        .container {
          max-width: 600px;
          margin: auto;
          padding: 20px;
          border: 1px solid #ddd;
          border-radius: 8px;
        }
        .footer {
          margin-top: 20px;
          font-size: 0.9em;
          color: #666;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Updated the membership!</h1>
        <p><strong>Name:</strong> ${user.name}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>Gym ID:</strong> ${user.gymid}</p>
       
        <p><strong>Subscription Duration:</strong> ${user.subendsin} days</p>
      </div>
      <div class="footer">
        <p>Thank you for choosing our gym.</p>
        <p>If you did not sign up for this service, please ignore this email.</p>
      </div>
    </body>
    </html>
  `;

    await sendEmail({
      email: user.email,
      subject: "membership upgraded",
      html: htmlMessage,
    });

    res.status(200).json({
      success: true,
      message: "Subscription and attendance updated successfully",
      user,
    });
  } catch (error) {
    next(error);
  }
});
exports.GetAllDetails = asyncHandler(async (req, res, next) => {
  const { gymemail, gymnumber, password } = req.body;
  if (!password) {
    return next(new errorHandler("Enter Password", 403));
  }
  if (!gymemail && !gymnumber) {
    return next(new errorHandler("Enter Email or Phone Number", 403));
  }
  let user;
  try {
    if (gymemail) {
      user = await User.findOne({ gymemail }).select("+password");
    }
    if (gymnumber && !user) {
      user = await User.findOne({ gymnumber }).select("+password");
    }
    if (!user) {
      return next(new errorHandler("User not found", 404));
    }
    const passwordMatch = await user.comparePassword(password);
    if (!passwordMatch) {
      return next(new errorHandler("Invalid Password", 403));
    }
    const gymUserIds = user.users;
    const gymUsers = await GymusersModel.find({
      gymid: { $in: gymUserIds },
    });
    let genderCount = {
      male: 0,
      female: 0,
    };
    let attendanceCount = {};
    const today = moment().startOf("day");
    for (let i = 0; i <= 10; i++) {
      const date = moment(today).subtract(i, "days").format("DD-MM-YYYY");
      attendanceCount[date] = 0;
    }
    gymUsers.forEach((gymUser) => {
      if (gymUser.gender === "male") {
        genderCount.male += 1;
      } else if (gymUser.gender === "female") {
        genderCount.female += 1;
      }
      if (gymUser.attendance instanceof Map) {
        gymUser.attendance.forEach((value, date) => {
          if (attendanceCount.hasOwnProperty(date) && value === "yes") {
            attendanceCount[date] += 1;
          }
        });
      } else {
        Object.keys(attendanceCount).forEach((date) => {
          if (gymUser.attendance && gymUser.attendance[date] === "yes") {
            attendanceCount[date] += 1;
          }
        });
      }
    });
    res.status(200).json({
      success: true,
      data: {
        gender: genderCount,
        attendance: attendanceCount,
      },
    });
  } catch (error) {
    next(error);
  }
});

exports.getAttendanceByDateRange = asyncHandler(async (req, res) => {
  try {
    const gymId = req.gym.id; // Get gymId from JWT auth middleware (req.gym.id)

    // Fetch the user based on gymId
    const gymUser = await User.findById(gymId);
    if (!gymUser) {
      return res
        .status(404)
        .json({ success: false, message: "Gym user not found" });
    }

    // Get users associated with this gym (user.users is assumed to be an array of user IDs)
    const associatedUsers = gymUser.users;

    // Parse the start and end dates from the query or body
    const { startDate, endDate } = req.body;
    const start = startDate
      ? moment(startDate, "DD-MM-YYYY")
      : moment().startOf("month");
    const end = endDate ? moment(endDate, "DD-MM-YYYY") : moment();

    // Find gym models associated with the users within the date range
    const attendanceData = await GymModel.find({
      userId: { $in: associatedUsers },
      "attendance.date": { $gte: start.toDate(), $lte: end.toDate() },
    });

    // Format and return the data with default as 0 for missing dates
    let attendanceSummary = {};

    // If there is no attendance, we create default 0 values for each date in the range
    let currentDate = moment(start);
    while (currentDate <= end) {
      const formattedDate = currentDate.format("DD-MM-YYYY");
      attendanceSummary[formattedDate] = 0; // Default value for missing dates
      currentDate = currentDate.add(1, "day");
    }

    // Iterate over found attendance data to update the summary
    attendanceData.forEach((record) => {
      const userAttendance = record.attendance;
      for (const [date, status] of Object.entries(userAttendance)) {
        if (attendanceSummary[date] !== undefined) {
          // Increase the count for each present ('yes') attendance
          if (status === "yes") {
            attendanceSummary[date] += 1; // Increment for each present
          }
        }
      }
    });

    return res.status(200).json({
      success: true,
      data: {
        users: associatedUsers.length,
        attendance: attendanceSummary,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});
