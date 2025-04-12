// portal_leaves.js
require("dotenv").config(); // Load environment variables from .env

const express = require("express");
const mongoose = require("mongoose");
const { verify } = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// Use environment variables
const PORT = process.env.PORT || 3001;
const PORTAL_MONGO_URI = process.env.portal_mongo_uri;
const JWT_SECRET = process.env.JWT_SECRET;

if (!PORTAL_MONGO_URI || !JWT_SECRET) {
  console.error(
    "Error: Missing required environment variables. Check your .env file."
  );
  process.exit(1);
}

// Connect to the portal MongoDB (using the 'test' database as per your URI)
mongoose
  .connect(PORTAL_MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to portal MongoDB"))
  .catch((err) => {
    console.error("Portal MongoDB connection error:", err);
    process.exit(1);
  });

// GET /api/my-leaves: returns leave records for the logged-in user.
app.get("/api/my-leaves", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = verify(token, JWT_SECRET);
    // IMPORTANT: Ensure that the token payload includes the user's email.
    // If not, modify your authentication token generation to include it.
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(400).json({ message: "Invalid token: email missing" });
    }

    // Query the 'leaves' collection for documents with this userEmail.
    const leaves = await mongoose.connection.db
      .collection("leaves")
      .find({ userEmail })
      .toArray();

    return res.status(200).json({ leaves });
  } catch (error) {
    console.error("Error fetching leaves:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Portal Leaves API running on port ${PORT}`);
});
