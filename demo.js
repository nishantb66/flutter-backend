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
    const userName = decoded.username || "User";
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