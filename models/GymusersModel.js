const mongoose = require("mongoose");
const validator = require("validator");

const GymUserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please Enter  username"],
    maxlength: [40, "username should not exceed morethan 40 characters"],
    minlength: [3, "username should not be lessthan 4 characters"],
  },
  email: {
    type: String,
    required: [true, "Please Enter User Email"],
    unique: true,
    validate: [validator.isEmail, "Please enter valid email"],
  },
  number: {
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
  gender: {
    type: String,
    required: true,
    enum: ["male", "female"],
  },
  height: {
    type: String,
    required: true,
  },
  gymid: {
    type: Number,
    required: true,
    unique: true,
  },
  weight: {
    type: String,
    required: true,
  },
  subscriptionStartDate: {
    type: Date,
    default: Date.now,
  },
  subscriptionEndDate: {
    type: Date,
  },
  subendsin: {
    type: Number,
    required: true,
  },
  role: {
    type: String,
    default: "User",
  },
  attendance: {
    type: Map,
    of: {
      type: String,
      enum: ["yes", "no", null],
      default: null,
    },
    default: {},
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
});

module.exports = mongoose.model("GymUsers", GymUserSchema);
