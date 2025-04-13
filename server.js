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

// Add this GET endpoint to fetch the logged-in user's team details
app.get("/api/teams", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Token expired or invalid" });
    }

    const userEmailFromToken = decoded.email;
    // Check if ?myTeam=1
    if (req.query.myTeam === "1") {
      // 1) Connect to portal DB -> test -> teams collection
      const testDb = portalConnection.useDb("test");
      const teamsCollection = testDb.collection("teams");

      // 2) Find the team where this user is leader or member
      const team = await teamsCollection.findOne({
        $or: [
          { leaderEmail: userEmailFromToken },
          { "members.email": userEmailFromToken },
        ],
      });

      if (!team) {
        // Not in any team
        return res.status(200).json({ inTeam: false });
      }

      // 3) Compare with the main DB's users collection (already connected by Mongoose)
      const usersCollectionMain = mongoose.connection.db.collection("users");

      // Leader name: if found => doc.username; else => "User."
      const leaderDoc = await usersCollectionMain.findOne({
        email: team.leaderEmail,
      });
      const leaderName =
        leaderDoc && leaderDoc.username ? leaderDoc.username : "User.";

      // 4) Build members array with name from main DB if found and convert invitedAt to IST
      const membersWithNames =
        team.members && team.members.length > 0
          ? await Promise.all(
              team.members.map(async (m) => {
                const userDoc = await usersCollectionMain.findOne({
                  email: m.email,
                });
                const memberName =
                  userDoc && userDoc.username ? userDoc.username : "User.";
                return {
                  email: m.email,
                  name: memberName,
                  invitedAt: m.invitedAt
                    ? new Date(m.invitedAt).toLocaleString("en-IN", {
                        timeZone: "Asia/Kolkata",
                      })
                    : null,
                  canAddMembers: m.canAddMembers || false,
                };
              })
            )
          : [];

      // 5) Transform joinRequests array: update requestedAt to IST.
      const joinRequests = (team.joinRequests || []).map((r) => ({
        ...r,
        requestedAt: r.requestedAt
          ? new Date(r.requestedAt).toLocaleString("en-IN", {
              timeZone: "Asia/Kolkata",
            })
          : null,
      }));

      // 6) Transform notice field (if exists) to display updatedAt in IST.
      const notice = team.notice
        ? {
            ...team.notice,
            updatedAt: team.notice.updatedAt
              ? new Date(team.notice.updatedAt).toLocaleString("en-IN", {
                  timeZone: "Asia/Kolkata",
                })
              : null,
          }
        : null;

      // 7) Build the response object with all required details.
      const responseTeam = {
        teamName: team.teamName,
        teamDescription: team.teamDescription,
        leaderEmail: team.leaderEmail,
        leaderName: leaderName,
        members: membersWithNames,
        createdAt: team.createdAt
          ? new Date(team.createdAt).toLocaleString("en-IN", {
              timeZone: "Asia/Kolkata",
            })
          : null,
        notice: notice,
        joinRequests: joinRequests,
      };

      const isLeader =
        team.leaderEmail.toLowerCase() === userEmailFromToken.toLowerCase();

      return res.status(200).json({
        inTeam: true,
        isLeader,
        team: responseTeam,
      });
    } else {
      // If query param is missing or invalid
      return res.status(400).json({ message: "Invalid query parameter" });
    }
  } catch (err) {
    console.error("Error fetching team details:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// New endpoint to fetch today's calendar events for the logged-in user
app.get("/api/calendar/today", async (req, res) => {
  try {
    // 1) Use portalConnection => test => calendarEvents collection
    const calendarEvents = portalConnection
      .useDb("test")
      .collection("calendarEvents");

    // 2) Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No auth token" });
    }
    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    const userEmail = decoded.email;

    // 3) Get the current date in IST (Asia/Kolkata)
    const now = new Date();
    // Convert to a Date object in IST:
    const nowIST = new Date(
      now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );
    const year = nowIST.getFullYear();
    const month = nowIST.getMonth();
    const day = nowIST.getDate();

    // Define the start and end of *today* in IST
    const startOfDayIST = new Date(year, month, day, 0, 0, 0, 0);
    const endOfDayIST = new Date(year, month, day, 23, 59, 59, 999);

    // Convert these IST boundaries to their UTC equivalents for querying
    // Since IST = UTC+5:30, subtract 5.5 hours worth of milliseconds
    const offsetMillis = 5.5 * 60 * 60 * 1000;
    const startUTC = new Date(startOfDayIST.getTime() - offsetMillis);
    const endUTC = new Date(endOfDayIST.getTime() - offsetMillis);

    // 4) Find all events for this user that fall within today's date boundaries (UTC)
    //    We assume the "date" field in MongoDB is stored as a proper Date object.
    const events = await calendarEvents
      .find({
        email: userEmail,
        date: { $gte: startUTC, $lte: endUTC },
      })
      .sort({ date: 1 }) // sort ascending by date
      .toArray();

    // 5) Convert relevant fields back to IST for display
    const eventsIST = events.map((ev) => ({
      ...ev,
      createdAt: ev.createdAt
        ? new Date(ev.createdAt).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          })
        : null,
      startTime: ev.startTime
        ? new Date(ev.startTime).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          })
        : null,
      endTime: ev.endTime
        ? new Date(ev.endTime).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          })
        : null,
      // The "date" field will remain as a Date in UTC by default
      // but you can also convert it if you'd like:
      // date: new Date(ev.date).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })
    }));

    return res.status(200).json({ events: eventsIST });
  } catch (err) {
    console.error("Error fetching today's calendar events:", err);
    return res.status(500).json({ message: err.message });
  }
});

// New: POST /api/notification
app.post("/api/notification", async (req, res) => {
  try {
    // Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userEmail = decoded.email;

    // Define a fixed notification message
    const notificationMessage = "An article is published by a user";

    // Use portalConnection to connect to the 'test' database and the notifications collection
    const testDb = portalConnection.useDb("test");
    const notifications = testDb.collection("notifications");

    // Create a notification record with fixed message text
    const notification = {
      recipientEmail: userEmail,
      message: notificationMessage,
      createdAt: new Date(),
      read: false,
    };

    await notifications.insertOne(notification);
    return res.status(201).json({ message: "Notification stored" });
  } catch (err) {
    console.error("Error in /api/notification:", err);
    return res.status(500).json({ message: err.message });
  }
});

// New: GET /api/notification -- fetch notifications for the logged-in user
app.get("/api/notification", async (req, res) => {
  try {
    // Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userEmail = decoded.email;

    const testDb = portalConnection.useDb("test");
    const notifications = testDb.collection("notifications");

    // Fetch all notifications for this user that are unread
    const notifs = await notifications.find({ recipientEmail: userEmail, read: false }).sort({ createdAt: -1 }).toArray();
    return res.status(200).json({ notifications: notifs });
  } catch (err) {
    console.error("Error fetching notifications:", err);
    return res.status(500).json({ message: err.message });
  }
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
