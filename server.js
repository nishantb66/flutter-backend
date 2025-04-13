// server.js
require("dotenv").config(); // Load environment variables from .env

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");

const User = require("./models/User");
const Otp = require("./models/Otp");
const Feedback = require("./models/Feedback");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Use environment variables
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const portal_mongo_uri = process.env.portal_mongo_uri;
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL = process.env.EMAIL;
const APP_PASS = process.env.APP_PASS;

if (!MONGODB_URI || !portal_mongo_uri || !JWT_SECRET || !EMAIL || !APP_PASS) {
  console.error(
    "Error: Missing required environment variables. Check your .env file."
  );
  process.exit(1);
}

// Connect to the main MongoDB (for auth and others)
mongoose
  .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to main MongoDB"))
  .catch((err) => {
    console.error("MongoDB connection error: ", err);
    process.exit(1);
  });

// Create a separate connection for portal data (leaves, reimbursements, tasks)
const portalConnection = mongoose.createConnection(portal_mongo_uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
portalConnection.on("error", (err) => {
  console.error("Portal MongoDB connection error: ", err);
});
portalConnection.once("open", () => {
  console.log("Connected to portal MongoDB");
});

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL,
    pass: APP_PASS,
  },
});

// Registration endpoint
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    // Include email in the token payload.
    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Forgot password endpoint: send OTP email.
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Email not registered" });

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otp = new Otp({ email, otp: otpCode });
    await otp.save();

    const mailOptions = {
      from: EMAIL,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otpCode}`,
    };
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).json({ message: "Error sending OTP email" });
      } else {
        return res.status(200).json({ message: "OTP sent to email" });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset password endpoint: verify OTP and update password.
app.post("/api/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const otpRecord = await Otp.findOne({ email, otp });
    if (!otpRecord)
      return res.status(400).json({ message: "Invalid or expired OTP" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ email }, { password: hashedPassword });
    await Otp.deleteOne({ _id: otpRecord._id });

    res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// My Leaves endpoint: returns leave records for the logged-in user.
// Uses the portalConnection and explicitly selects the 'test' database.
app.get("/api/my-leaves", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }

    const testDb = portalConnection.useDb("test");
    const leaves = await testDb
      .collection("leaves")
      .find({ userEmail })
      .toArray();

    return res.status(200).json({ leaves });
  } catch (error) {
    console.error("Error fetching leaves:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// My Reimbursements endpoint: returns reimbursement records for the logged-in user.
// Uses the portalConnection (with the 'test' database) and queries the "reimbursements" collection.
app.get("/api/my-reimbursements", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }

    const testDb = portalConnection.useDb("test");
    const reimbursements = await testDb
      .collection("reimbursements")
      .find({ email: userEmail })
      .toArray();

    return res.status(200).json({ reimbursements });
  } catch (error) {
    console.error("Error fetching reimbursements:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// New: My Tasks endpoint: returns task documents (from "assignment" collection)
// for the logged-in user, using the portalConnection and the "test" database.
app.get("/api/my-tasks", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }
    const testDb = portalConnection.useDb("test");
    // Here, we follow the pattern to return both tasks created by the user and tasks assigned to them.
    const createdTasks = await testDb
      .collection("assignment")
      .find({ "createdBy.email": userEmail })
      .toArray();
    const assignedTasks = await testDb
      .collection("assignment")
      .find({ "assignedTo.email": userEmail })
      .toArray();
    return res
      .status(200)
      .json({ created: createdTasks, assigned: assignedTasks });
  } catch (error) {
    console.error("Error fetching tasks:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// New: Feedback endpoint
app.post("/api/feedback", async (req, res) => {
  // Verify token from headers
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
  const userEmail = decoded.email;
  if (!userEmail) {
    return res.status(400).json({ message: "Invalid token: email missing" });
  }

  // Destructure feedback fields from request body
  const {
    enterpriseManagementSaaS,
    userExperience,
    intelligenceRating,
    improvements,
    enterprisePortalRating,
  } = req.body;

  // Basic validation of required fields (more advanced validation can be added)
  if (
    !enterpriseManagementSaaS ||
    !userExperience ||
    intelligenceRating == null ||
    !improvements ||
    enterprisePortalRating == null
  ) {
    return res
      .status(400)
      .json({ message: "Please provide all required feedback fields" });
  }

  try {
    // Create and save the feedback document
    const feedback = new Feedback({
      userEmail,
      enterpriseManagementSaaS,
      userExperience,
      intelligenceRating,
      improvements,
      enterprisePortalRating,
    });
    await feedback.save();
    res.status(201).json({ message: "Feedback submitted successfully" });
  } catch (err) {
    console.error("Error submitting feedback:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ------------------------------
// Meeting Rooms Booking Endpoints
// ------------------------------

// GET /api/meeting
// Retrieve all meeting room bookings from the "meetingRooms" collection in the "test" database.
app.get("/api/meeting", async (req, res) => {
  try {
    const testDb = portalConnection.useDb("test");
    const meetingRooms = testDb.collection("meetingRooms");

    // Ensure TTL index is created for automatic document removal after meeting end time.
    await meetingRooms.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 });

    const rooms = await meetingRooms.find({}).toArray();
    return res.status(200).json(rooms);
  } catch (error) {
    console.error("GET /api/meeting error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/meeting
// Books a meeting room. It verifies the user's token, checks data integrity, and then upserts the booking
app.post("/api/meeting", async (req, res) => {
  try {
    // 1. Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }
    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid token" });
    }

    // 2. Parse incoming data
    const {
      roomId,
      meetingStart,
      meetingEnd,
      topic,
      department,
      numEmployees,
      hostDesignation,
    } = req.body;
    if (
      !roomId ||
      !meetingStart ||
      !meetingEnd ||
      !topic ||
      !department ||
      !numEmployees ||
      !hostDesignation
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const startDate = new Date(meetingStart);
    const endDate = new Date(meetingEnd);

    if (endDate <= startDate) {
      return res
        .status(400)
        .json({ message: "Meeting End Time must be after Start Time" });
    }

    // 3. Connect to the test database and obtain the meetingRooms collection
    const testDb = portalConnection.useDb("test");
    const meetingRooms = testDb.collection("meetingRooms");

    // Ensure TTL index exists so that documents auto-delete after meetingEnd time.
    await meetingRooms.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 });

    // 4. Check if room is already booked
    const existing = await meetingRooms.findOne({ roomId });
    if (existing && existing.booked) {
      return res.status(400).json({ message: "Room is already booked" });
    }

    // 5. Upsert the booking with UTC times and include a TTL field (expireAt)
    await meetingRooms.updateOne(
      { roomId },
      {
        $set: {
          roomId: roomId,
          booked: true,
          bookingDetails: {
            hostName: decoded.username, // Assumes your token payload carries a 'username'
            hostEmail: decoded.email,
            hostDesignation: hostDesignation,
            topic: topic,
            department: department,
            meetingStart: startDate.toISOString(),
            meetingEnd: endDate.toISOString(),
            numEmployees: numEmployees,
          },
          expireAt: endDate, // MongoDB TTL index will remove the document after this time
        },
      },
      { upsert: true }
    );

    return res.status(200).json({ message: "Room booked successfully" });
  } catch (error) {
    console.error("POST /api/meeting error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
