// models/Feedback.js
const mongoose = require("mongoose");

const FeedbackSchema = new mongoose.Schema(
  {
    // Email of the user giving feedback, automatically extracted from token on submission
    userEmail: { type: String, required: true },
    // Feedback options for enterprise management SaaS awareness
    enterpriseManagementSaaS: {
      type: String,
      enum: ["Yes", "No", "I don't know"],
      required: true,
    },
    // Feedback on user experience
    userExperience: {
      type: String,
      enum: ["Very", "Decent", "Not so", "I don't know"],
      required: true,
    },
    // Rating of intelligence features (out of 5)
    intelligenceRating: { type: Number, required: true },
    // Text field for suggestions or improvements
    improvements: { type: String, required: true },
    // Rating of Enterprise Portal overall (out of 5)
    enterprisePortalRating: { type: Number, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Feedback", FeedbackSchema);
