const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { type } = require("os");

const userSchema = new mongoose.Schema({
  gymname: {
    type: String,
    required: [true, "Please Enter Gym Username"],
    maxlength: [40, "username should not exceed morethan 40 characters"],
    minlength: [3, "username should not be lessthan 4 characters"],
  },
  gymemail: {
    type: String,
    required: [true, "Please Enter User Email"],
    unique: true,
    validate: [validator.isEmail, "Please enter valid email"],
  },
  gymnumber: {
    type: Number,
    unique: true,
    validate: {
      validator: function (v) {
        return /^\d{10}$/.test(v.toString());
      },
      message: (props) => `${props.value} is not a valid 10-digit number!`,
    },
    required: true,
  },
  password: {
    type: String,
    required: [true, "Please Enter User Password"],
    minlength: [8, "password should be greaterthan 8 characters"],
    select: false,
  },

  gymaddress: {
    type: String,
    required: true,
  },
  gymsubsription: {
    type: String,
    required: true,
    enum: ["trial", "pro"],
  },
  subscriptionStartDate: {
    type: Date,
    default: Date.now,
  },
  gymlicense: {
    type: String,
    required: true,
  },
  gymzone: {
    type: String,
    required: true,
  },
  ownernumber: {
    type: Number,
    unique: true,
    validate: {
      validator: function (v) {
        return /^\d{10}$/.test(v.toString());
      },
      message: (props) => `${props.value} is not a valid 10-digit number!`,
    },
    required: true,
  },

  owneremail: {
    type: String,
    required: [true, "Please Enter User Email"],
    unique: true,
    validate: [validator.isEmail, "Please enter valid email"],
  },
  ownerpan: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return v.length === 10;
      },
      message: (props) => `${props.value} is not a PAN `,
    },
  },
  owneraadhar: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return v.trim().length === 12;
      },
      message: (props) => `${props.value} is not a Aadhar `,
    },
  },
  role: {
    type: String,
    default: "Gym",
  },

  resetPasswordToken: String,
  resetPasswordExpire: Date,
});

// pre hook to check weather password is modified
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  this.password = await bcrypt.hash(this.password, 10);
});

// generate JWT token
userSchema.methods.jwtToken = function () {
  let expiresIn;

  if (this.gymsubsription === "trial") {
    const trialPeriod = 15 * 24 * 60 * 60 * 1000;
    const currentTime = Date.now();
    const trialEndTime = this.subscriptionStartDate.getTime() + trialPeriod;

    if (trialEndTime > currentTime) {
      const remainingDays = Math.ceil(
        (trialEndTime - currentTime) / (24 * 60 * 60 * 1000)
      );
      expiresIn = `${remainingDays}d`;
    } else {
      throw new Error("Trial period has expired");
    }
  } else {
    expiresIn = process.env.jwt_expire;
  }
  console.log(expiresIn);
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn,
  });
};

// password compare
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.resetToken = function () {
  const token = crypto.randomBytes(20).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  this.resetPasswordToken = hashedToken;
  this.resetPasswordExpire = Date.now() + 1000 * 60 * 60 * 24 * 15;
  return token;
};
userSchema.methods.isTrialExpired = function () {
  if (this.gymsubsription === "trial") {
    const trialPeriod = 15 * 24 * 60 * 60 * 1000;
    const currentDate = Date.now();
    return currentDate - this.subscriptionStartDate > trialPeriod;
  }
  return false;
};

module.exports = mongoose.model("User", userSchema);
