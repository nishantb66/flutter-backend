// models/Otp.js
const mongoose = require("mongoose");

const OtpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 600 }, // expire after 600 seconds (10 minutes)
});

module.exports = mongoose.model("Otp", OtpSchema);
