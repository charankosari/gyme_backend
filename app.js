const express = require("express");
const app = express();
const user = require("./routes/userRouter");
const errorMiddleware = require("./middleware/error");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const cors = require("cors");

// cors
// app.use(cors())
app.use(cors({ credentials: true, origin: true }));
// cookie parser
app.use(cookieParser());
// morgan logger [to show the request details in console]
app.use(logger("tiny"));
// body parser
app.use(express.json());
// express.urlencoded({extended: false})
app.use("/api/gymee", user);
// order route
// errorHandler Middleware
app.use(errorMiddleware);

// to get paymentgateway key
// app.get("/payment/getKey",(req,res,next)=>res.status(200).json({key:process.env.RAZORPAY_ID}))

module.exports = app;
