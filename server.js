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
const Groq = require("groq-sdk");
const http = require("http");
const { Server } = require("socket.io");

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

// ------------------------------
// Announcements Endpoints
// ------------------------------

// In-memory array of announcements. In production, you might store these in a database.
const announcements = [
  {
    id: 1,
    title: "New Feature Release",
    description: "Now user can view tasks in team and tasks section",
    fullText:
      "We have updated a new feature in team and tasks section where users can now check on the tasks assigned to them by team leader. This feature will enable updates to the user without requirement of laptop or desktop to check on assigned tasks quickly",
  },
  {
    id: 2,
    title: "Maintenance and update Schedule",
    description:
      "App maintenance and update is scheduled for everyday for 1 to 2 hrs.",
    fullText:
      "Please note that system maintenance is scheduled for this weekend. The maintenance window is planned to take place on Saturday from 2 PM to 6 PM. Kindly plan your work accordingly.",
  },
  {
    id: 3,
    title: "Miscellaneous",
    description: "More updates on app will be visible here.",
    fullText: "Stay tunned",
  },
];

// Endpoint: Get all announcements (for carousel)
app.get("/api/announcements", (req, res) => {
  return res.status(200).json({ announcements });
});

// Endpoint: Get a specific announcement detail by ID
app.get("/api/announcement/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const announcement = announcements.find((a) => a.id === id);
  if (announcement) {
    return res.status(200).json(announcement);
  } else {
    return res.status(404).json({ message: "Announcement not found" });
  }
});

// ------------------------------
// Registration endpoint
// ------------------------------
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

// ------------------------------
// Login endpoint (portal DB 'test' → 'users' collection)
// ------------------------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Look up user in the portal DB
    const testDb = portalConnection.useDb("test");
    const user = await testDb.collection("users").findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // 2. Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // 3. Sign token with email, name, emp_id, role
    const token = jwt.sign(
      {
        email: user.email,
        name: user.name,
        emp_id: user.emp_id,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "6d" }
    );

    // 4. Return token
    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ------------------------------
// Forgot password endpoint: send OTP email.
// ------------------------------
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

// ------------------------------
// Reset password endpoint: verify OTP and update password.
// ------------------------------
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

// ------------------------------
// My Leaves endpoint
// ------------------------------
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

// ------------------------------
// My Reimbursements endpoint
// ------------------------------
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

// ------------------------------
// My Tasks endpoint
// ------------------------------
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

// ------------------------------
// Feedback endpoint
// ------------------------------
app.post("/api/feedback", async (req, res) => {
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
  const {
    enterpriseManagementSaaS,
    userExperience,
    intelligenceRating,
    improvements,
    enterprisePortalRating,
  } = req.body;
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
app.get("/api/meeting", async (req, res) => {
  try {
    const testDb = portalConnection.useDb("test");
    const meetingRooms = testDb.collection("meetingRooms");
    await meetingRooms.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 });
    const rooms = await meetingRooms.find({}).toArray();
    return res.status(200).json(rooms);
  } catch (error) {
    console.error("GET /api/meeting error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/meeting", async (req, res) => {
  try {
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
    const testDb = portalConnection.useDb("test");
    const meetingRooms = testDb.collection("meetingRooms");
    await meetingRooms.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 });
    const existing = await meetingRooms.findOne({ roomId });
    if (existing && existing.booked) {
      return res.status(400).json({ message: "Room is already booked" });
    }
    await meetingRooms.updateOne(
      { roomId },
      {
        $set: {
          roomId: roomId,
          booked: true,
          bookingDetails: {
            hostName: decoded.name,
            hostEmail: decoded.email,
            hostDesignation: hostDesignation,
            topic: topic,
            department: department,
            meetingStart: startDate.toISOString(),
            meetingEnd: endDate.toISOString(),
            numEmployees: numEmployees,
          },
          expireAt: endDate,
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

// ------------------------------
// Team Details Endpoint
// ------------------------------
app.get("/api/teams", async (req, res) => {
  try {
    // 1. Verify JWT
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
    const userEmailFromToken = (decoded.email || "").trim().toLowerCase();

    // 2. Only handle if ?myTeam=1
    if (req.query.myTeam !== "1") {
      return res.status(400).json({ message: "Invalid query parameter" });
    }

    // 3. Use portalConnection for both teams AND users
    const portalTestDb = portalConnection.useDb("test");
    const teamsCollection = portalTestDb.collection("teams");
    const usersCollection = portalTestDb.collection("users");

    // 4. Find the team document
    const team = await teamsCollection.findOne({
      $or: [
        { leaderEmail: { $regex: new RegExp(`^${userEmailFromToken}$`, "i") } },
        {
          "members.email": {
            $regex: new RegExp(`^${userEmailFromToken}$`, "i"),
          },
        },
      ],
    });

    if (!team) {
      return res.status(200).json({ inTeam: false });
    }

    // 5. Lookup leader’s name from portal DB
    const leaderDoc = await usersCollection.findOne({
      email: { $regex: new RegExp(`^${team.leaderEmail}$`, "i") },
    });
    const leaderName = leaderDoc && leaderDoc.name ? leaderDoc.name : "User";

    // 6. Build members array with names also from portal DB
    const membersWithNames = Array.isArray(team.members)
      ? await Promise.all(
          team.members.map(async (m) => {
            const userDoc = await usersCollection.findOne({
              email: { $regex: new RegExp(`^${m.email}$`, "i") },
            });
            return {
              email: m.email,
              name: userDoc && userDoc.name ? userDoc.name : "User",
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

    // 7. Process join requests & notice timestamps
    const joinRequests = (team.joinRequests || []).map((r) => ({
      ...r,
      requestedAt: r.requestedAt
        ? new Date(r.requestedAt).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          })
        : null,
    }));
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

    // 8. Assemble the response payload
    const responseTeam = {
      _id: team._id.toString(),
      teamName: team.teamName,
      teamDescription: team.teamDescription,
      leaderEmail: team.leaderEmail,
      leaderName,
      members: membersWithNames,
      createdAt: team.createdAt
        ? new Date(team.createdAt).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          })
        : null,
      notice,
      joinRequests,
    };

    // 9. Determine leadership flag
    const isLeader =
      team.leaderEmail.trim().toLowerCase() === userEmailFromToken;

    // 10. Return
    return res.status(200).json({
      inTeam: true,
      isLeader,
      team: responseTeam,
    });
  } catch (err) {
    console.error("Error fetching team details:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------------------
// Calendar Events Endpoint for Today
// ------------------------------
app.get("/api/calendar/today", async (req, res) => {
  try {
    const calendarEvents = portalConnection
      .useDb("test")
      .collection("calendarEvents");
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
    const now = new Date();
    const nowIST = new Date(
      now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );
    const year = nowIST.getFullYear();
    const month = nowIST.getMonth();
    const day = nowIST.getDate();
    const startOfDayIST = new Date(year, month, day, 0, 0, 0, 0);
    const endOfDayIST = new Date(year, month, day, 23, 59, 59, 999);
    const offsetMillis = 5.5 * 60 * 60 * 1000;
    const startUTC = new Date(startOfDayIST.getTime() - offsetMillis);
    const endUTC = new Date(endOfDayIST.getTime() - offsetMillis);
    const events = await calendarEvents
      .find({ email: userEmail, date: { $gte: startUTC, $lte: endUTC } })
      .sort({ date: 1 })
      .toArray();
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
    }));
    return res.status(200).json({ events: eventsIST });
  } catch (err) {
    console.error("Error fetching today's calendar events:", err);
    return res.status(500).json({ message: err.message });
  }
});

// ------------------------------
// Latest Articles Endpoint
// ------------------------------
app.get("/api/articles/latest", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Please log in to view" });
    }
    const token = authHeader.split(" ")[1];
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Please log in to view" });
    }
    const testDb = portalConnection.useDb("test");
    const articlesCollection = testDb.collection("articles");
    const articles = await articlesCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray();
    return res.status(200).json({ articles });
  } catch (error) {
    console.error("Error fetching latest articles:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// ------------------------------
// AI Chat Endpoint
// ------------------------------
const groq = new Groq({ apiKey: process.env.GROQ });
function sanitizeRole(role) {
  switch (role) {
    case "system":
    case "assistant":
    case "user":
      return role;
    case "ai":
    case "bot":
      return "assistant";
    default:
      return "user";
  }
}

app.post("/api/chat", async (req, res) => {
  try {
    // 1. Verify token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Please log in to view" });
    }
    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Please log in to view" });
    }
    const userName = decoded.name || "User";
    const userEmail = decoded.email || "";

    // 2. Parse the incoming messages array
    const userMessages = req.body.messages;
    if (!Array.isArray(userMessages)) {
      return res.status(400).json({ message: "Invalid messages payload" });
    }

    // 3. Sanitize roles in user's messages
    const sanitizedUserMessages = userMessages.map((msg) => ({
      ...msg,
      role: sanitizeRole(msg.role),
    }));

    // 4. Build the top-level system instructions
    //    Use allowed roles: "system", "assistant", or "user"
    const greetingMessage = {
      role: "system",
      content: `Hello ${userName}, your email is ${userEmail}.`,
    };
    const platformMemory = {
      role: "system",
      content: `Enterprise Portal - Feature Documentation
Introduction
Enterprise Portal is an MVP that centralizes workplace operations including task management, leave applications, customer complaints, meeting scheduling, reimbursements, surveys, and AI assistance.

Key Features
Dashboard - Central hub with intuitive navigation to all portal features.
Customer Complaints - Log, track, and filter complaints with AI-powered resolution assistance.
Leave Management - Submit leave requests with AI assistance for queries.
Meeting Scheduling - Book rooms, set meeting details, and view upcoming sessions.
Task Management - Create, assign, and track tasks with status indicators.
Room Booking - Reserve meeting spaces with integration to EP Teams workspace.
Reimbursement - Submit and track expense reimbursement requests with document attachment.
Survey System - Anonymous workplace surveys with real-time data streaming to PowerBI.
Calendar & Reminders - Color-coded events with AWS-powered email notifications.
PDF Document Reader - AI-powered tool to interact with PDF content.
Employee Directory - Search users and send inbox messages.
EP Teams Workspace - Advanced collaboration environment with role-based access.
AI Assistance - Contextual help across multiple portal functions.
Future Enhancements
Enhanced AI capabilities, role-based access, third-party integrations, analytics, mobile app development, and HR system integration.
Conclusion
Enterprise Portal streamlines workplace operations through integrated features with AI assistance, designed to evolve into a comprehensive enterprise resource management system.
Developed by: Nishant Baruah`,
    };

    // 5. Combine everything
    const allMessages = [
      greetingMessage,
      platformMemory,
      ...sanitizedUserMessages,
    ];

    // 6. Call Groq with "stream": false => single JSON result
    const chatCompletion = await groq.chat.completions.create({
      messages: allMessages,
      model: "llama3-70b-8192",
      temperature: 1,
      max_completion_tokens: 512,
      top_p: 1,
      stream: false,
      stop: null,
    });

    // 7. For non-streaming, the entire response is in chatCompletion.choices.
    const reply = chatCompletion?.choices?.[0]?.message?.content || "";
    return res.status(200).json({ reply });
  } catch (error) {
    console.error("Chat error:", error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.toString() });
  }
});

// ------------------------------
// My Tasks (Assigned) Endpoint
// ------------------------------
app.get("/api/tasks", async (req, res) => {
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
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }
    const testDb = portalConnection.useDb("test");
    const tasks = await testDb
      .collection("tasks")
      .find({ "assignedTo.email": userEmail })
      .toArray();
    const filteredTasks = tasks.map((task) => ({
      taskName: task.taskName,
      deadline: task.deadline,
      urgency: task.urgency,
      updatedAt: task.updatedAt,
    }));
    return res.status(200).json({ tasks: filteredTasks });
  } catch (error) {
    console.error("Error fetching tasks:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------------------
// Platform Updates Endpoint
// ------------------------------

// In-memory array for platform updates – admin can update these objects.
const platformUpdates = [
  {
    id: 1,
    title: "Platform Intelligence - Image Analysis",
    date: "2025-04-10",
    isNew: true,
    description:
      "New feature in ContentHub for analysing images in detail, powered by the new llama 4 scout model.",
  },
  {
    id: 2,
    title: "System maintenance scheduled",
    date: "2025-04-27",
    isNew: false,
    description:
      "The platform will undergo maintenance with improvements in security and user experience.",
  },
  {
    id: 3,
    title: "On-Planning Calendar Update",
    date: "2025-04-29",
    isNew: false,
    description:
      "A new calendar feature is now available to enable a more personalized user experience.",
  },
  // Admin can add more update objects or remove any existing one here.
];

// Endpoint: Get all platform updates.
app.get("/api/platformupdates", (req, res) => {
  return res.status(200).json({ updates: platformUpdates });
});

// ------------------------------
// Profile Endpoint
// ------------------------------
app.get("/api/profile", async (req, res) => {
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
      return res.status(401).json({ message: "Invalid token" });
    }
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Email not found in token" });
    }
    // Use the portalConnection (from portal_mongo_uri) for the "test" database.
    const testDb = portalConnection.useDb("test");
    // Find a user document where the embedded profile.email matches the token's email.
    const userDoc = await testDb
      .collection("users")
      .findOne({ "profile.email": userEmail });
    if (!userDoc) {
      return res.status(404).json({ message: "User profile not found" });
    }
    return res.status(200).json({ profile: userDoc.profile });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

/********************************************************************
 * GET /api/teams/members
 * Returns the list of members (and the leader) in the team to which
 * the user (as determined by token) currently belongs.
 ********************************************************************/
app.get("/api/teams/members", async (req, res) => {
  try {
    // 1. Check and verify JWT token
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

    const userEmailFromToken = (decoded.email || "").trim().toLowerCase();

    // 2. Check if user is in a team
    const portalTestDb = portalConnection.useDb("test");
    const teamsCollection = portalTestDb.collection("teams");

    // Find team where user is either the leader or a member
    const team = await teamsCollection.findOne({
      $or: [
        { leaderEmail: { $regex: new RegExp(`^${userEmailFromToken}$`, "i") } },
        {
          "members.email": {
            $regex: new RegExp(`^${userEmailFromToken}$`, "i"),
          },
        },
      ],
    });

    if (!team) {
      // User is not in any team
      return res.status(404).json({
        message: "You are not currently a member of any team.",
      });
    }

    // 3. Get leader name from portal DB’s users collection
    const usersCollectionPortal = portalTestDb.collection("users");
    const leaderDoc = await usersCollectionPortal.findOne({
      email: { $regex: new RegExp(`^${team.leaderEmail}$`, "i") },
    });
    const leaderName = leaderDoc && leaderDoc.name ? leaderDoc.name : "User";

    // 4. Build the array of members, attaching name if found
    const membersWithNames = Array.isArray(team.members)
      ? await Promise.all(
          team.members.map(async (m) => {
            const userDoc = await usersCollectionPortal.findOne({
              email: { $regex: new RegExp(`^${m.email}$`, "i") },
            });
            const memberName = userDoc && userDoc.name ? userDoc.name : "User";
            return {
              email: m.email,
              name: memberName,
              // any other fields you want
            };
          })
        )
      : [];

    // 5. Return final JSON
    return res.status(200).json({
      leader: {
        email: team.leaderEmail,
        name: leaderName,
      },
      members: membersWithNames,
    });
  } catch (err) {
    console.error("Error fetching team members:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------------------
// Manager Access Status endpoint
// ------------------------------
app.get("/api/manager-access", async (req, res) => {
  try {
    // 1. Verify JWT in Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    // 2. Extract email
    const userEmail = (decoded.email || "").trim().toLowerCase();
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }

    // 3. Query the portal (test) DB’s managerAccess collection
    const testDb = portalConnection.useDb("test");
    const record = await testDb
      .collection("managerAccess")
      .findOne({ userEmail });

    // 4. If no request was ever made:
    if (!record) {
      return res.status(200).json({
        status: "None",
        createdAt: null,
      });
    }

    // 5. Return status and createdAt (as ISO string)
    return res.status(200).json({
      status: record.status, // "Approved" | "Rejected" | "Pending"
      createdAt: record.createdAt, // e.g. 2025-04-06T22:21:57.542Z
    });
  } catch (err) {
    console.error("GET /api/manager-access error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// near the top of server.js, after you set up portalConnection:
const meetingsColl = portalConnection.useDb("test").collection("meetings");
const inventoryColl = portalConnection
  .useDb("test")
  .collection("personalInventory");

// …later, replace your old /api/ai-query with this:

app.post("/api/ai-query", async (req, res) => {
  try {
    // (1) Verify JWT
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    const empId = decoded.emp_id;
    const userName = decoded.name || "User";

    // (2) Fetch this user’s meetings
    const rawMeetings = await meetingsColl
      .find({
        $or: [{ hostEmpId: empId }, { invitedEmpIds: empId }],
      })
      .toArray();

    // (3) Convert each meeting’s times into IST and include hostName
    const meetings = rawMeetings.map((m) => ({
      meetingRoom: m.meetingRoom,
      department: m.department,
      hostName: m.hostName,
      hostDesignation: m.hostDesignation,
      hostEmpId: m.hostEmpId,
      invitedEmpIds: m.invitedEmpIds,
      startTimeIST: new Date(m.startTime).toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
      }),
      endTimeIST: new Date(m.endTime).toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
      }),
    }));

    // (4) Fetch this user’s inventory (omit the large base64)
    const inventory = await inventoryColl
      .find({ empId: empId })
      .project({ fileData: 0 })
      .toArray();

    // (5) Get “today” in IST
    const todayIST = new Date().toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
    });

    // (6) Build the system prompt
    const systemPrompt = {
      role: "system",
      content: `
You are a secure AI assistant for Enterprise Portal.
Current date/time (IST): ${todayIST}

You may only answer using this specific user’s data:
• Username: ${userName}
• Employee ID: ${empId}

Meetings (times in IST):
${JSON.stringify(meetings, null, 2)}

Personal inventory items:
${JSON.stringify(inventory, null, 2)}

Under no circumstances reveal or reference any other user’s records.
Always treat the above as the *only* source of truth.
`.trim(),
    };

    // (7) Sanitize & combine incoming messages
    if (!Array.isArray(req.body.messages)) {
      return res
        .status(400)
        .json({ message: "Bad payload: messages must be an array" });
    }
    const userMsgs = req.body.messages.map((m) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: String(m.content),
    }));
    const allMessages = [systemPrompt, ...userMsgs];

    // (8) Call Groq
    const chatCompletion = await groq.chat.completions.create({
      messages: allMessages,
      model: "llama3-70b-8192",
      temperature: 1,
      max_completion_tokens: 512,
      top_p: 1,
      stream: false,
    });

    const reply = chatCompletion.choices?.[0]?.message?.content || "";
    return res.status(200).json({ reply });
  } catch (error) {
    console.error("AI‐Query error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// ------------------------------
// Team Chats History Endpoint
// ------------------------------
app.get("/api/teamchats/:teamId", async (req, res) => {
  try {
    const { teamId } = req.params;
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Invalid token." });
    }
    const testDb = portalConnection.useDb("test");
    const teamChatsCollection = testDb.collection("teamchats");
    // Retrieve messages for this team sorted by timestamp (oldest first)
    const messages = await teamChatsCollection
      .find({ teamId })
      .sort({ timestamp: 1 })
      .toArray();
    return res.status(200).json({ messages });
  } catch (error) {
    console.error("Error loading team chats:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Create HTTP server and attach Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Adjust if needed
  },
});

io.on("connection", (socket) => {
  console.log("New client connected:", socket.id);

  // Listen for client joining a team room
  socket.on("joinTeam", async (data) => {
    try {
      const { teamId, token } = data;
      if (!teamId || !token) {
        socket.emit("error", {
          message: "Missing teamId or authentication token.",
        });
        return;
      }

      // Verify token & parse email in lowercase
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (err) {
        socket.emit("error", { message: "Invalid token." });
        return;
      }
      const userEmail = (decoded.email || "").trim().toLowerCase();

      // Get the team document from the "teams" collection
      const testDb = portalConnection.useDb("test");
      const team = await testDb.collection("teams").findOne({
        _id: new mongoose.Types.ObjectId(teamId),
      });
      if (!team) {
        socket.emit("error", { message: "Team not found." });
        return;
      }

      // Check membership: compare leaderEmail and members.email case-insensitively
      const leaderEmail = (team.leaderEmail || "").trim().toLowerCase();
      const isLeader = leaderEmail === userEmail;
      const isMember =
        Array.isArray(team.members) &&
        team.members.some(
          (m) => (m.email || "").trim().toLowerCase() === userEmail
        );

      if (!isLeader && !isMember) {
        socket.emit("error", { message: "Not authorized to join this team." });
        return;
      }

      // Join the Socket.IO room named "team_<teamId>"
      const room = "team_" + teamId;
      socket.join(room);
      console.log(`Socket ${socket.id} joined room ${room}`);
      socket.emit("joinedTeam", { teamId });
    } catch (error) {
      console.error("joinTeam error:", error);
      socket.emit("error", { message: "Error joining team." });
    }
  });

  // NEW: Listen for "typing" events and broadcast to others in the room
  socket.on("typing", (data) => {
    try {
      const { teamId, token, typing } = data;
      if (!teamId || !token) return;
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (err) {
        return;
      }
      const userEmail = (decoded.email || "").trim().toLowerCase();
      const userName = decoded.name || "User";
      // Broadcast the typing status to everyone in the room except the sender.
      socket.to("team_" + teamId).emit("typing", {
        senderEmail: userEmail,
        senderName: userName,
        typing: typing,
      });
    } catch (error) {
      console.error("Typing event error:", error);
    }
  });

  // Listen for team chat messages with reply-to support
  socket.on("teamMessage", async (data) => {
    try {
      // Accept an optional replyTo field.
      const { teamId, token, message, replyTo } = data;
      if (!teamId || !token || !message) {
        socket.emit("error", { message: "Missing required fields." });
        return;
      }

      // Verify token & get normalized email
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (err) {
        socket.emit("error", { message: "Invalid token." });
        return;
      }
      const userEmail = (decoded.email || "").trim().toLowerCase();
      const userName = decoded.name || "User";

      // Build the message document – include replyTo if provided.
      const testDb = portalConnection.useDb("test");
      const teamChatsCollection = testDb.collection("teamchats");
      const messageDoc = {
        teamId,
        senderEmail: userEmail,
        senderName: userName,
        message,
        timestamp: new Date(),
      };
      if (replyTo != null) {
        messageDoc.replyTo = replyTo;
      }
      await teamChatsCollection.insertOne(messageDoc);

      // Broadcast the new message to all sockets in the team room
      io.to("team_" + teamId).emit("newTeamMessage", messageDoc);
    } catch (error) {
      console.error("teamMessage error:", error);
      socket.emit("error", { message: "Error sending team message." });
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// Start the server using the HTTP server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
