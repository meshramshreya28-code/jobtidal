require("dotenv").config(); // ✅ ENV support

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// ✅ Use env variables
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/jobtidal";

app.use(cors());
app.use(express.json());

/* ================= DB CONNECTION ================= */
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => {
    console.error("DB Error:", err.message);
    process.exit(1);
  });

/* ================= ERROR HANDLER ================= */
function errorHandler(err, req, res, next) {
  console.error(err.stack);
  res.status(500).json({ message: err.message || "Internal Server Error" });
}

/* ================= AUTH MIDDLEWARE ================= */
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function roleMiddleware(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

/* ================= MODELS ================= */
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // ✅ ownership
  applications: [
    {
      name: String,
      email: String,
      resume: String, // should be URL
      note: String,
      date: { type: Date, default: Date.now }
    }
  ]
}, { timestamps: true });

const Job = mongoose.model("Job", jobSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "company", "admin"], default: "user" }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ================= VALIDATION HELPERS ================= */
function validateRegister({ username, password }) {
  if (!username || username.length < 3) return "Username too short";
  if (!password || password.length < 5) return "Password too short";
  return null;
}

/* ================= ROUTES ================= */

// TEST
app.get("/", (req, res) => {
  res.send("JobTidal Backend Working 🚀");
});

/* ================= AUTH ================= */
app.post("/register", async (req, res, next) => {
  try {
    const error = validateRegister(req.body);
    if (error) return res.status(400).json({ message: error });

    const { username, password, role } = req.body;

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ message: "Username already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashed,
      role: role || "user"
    });

    await user.save();
    res.status(201).json({ message: "Registered successfully" });

  } catch (err) {
    next(err);
  }
});

app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Missing credentials" });
    }

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, role: user.role });

  } catch (err) {
    next(err);
  }
});

/* ================= JOBS ================= */

// GET jobs
app.get("/jobs", async (req, res, next) => {
  try {
    const jobs = await Job.find().select("-applications");
    res.json(jobs);
  } catch (err) {
    next(err);
  }
});

// POST job (ONLY company/admin)
app.post("/jobs", authMiddleware, roleMiddleware("company", "admin"), async (req, res, next) => {
  try {
    const { title, company, location } = req.body;

    if (!title || !company || !location) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const job = new Job({
      title,
      company,
      location,
      createdBy: req.user.id
    });

    await job.save();
    res.status(201).json({ message: "Job created" });

  } catch (err) {
    next(err);
  }
});

// APPLY
app.post("/apply/:id", authMiddleware, async (req, res, next) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ message: "Job not found" });

    const { name, email } = req.body;
    if (!name || !email) {
      return res.status(400).json({ message: "Name & email required" });
    }

    job.applications.push(req.body);
    await job.save();

    res.json({ message: "Applied successfully" });

  } catch (err) {
    next(err);
  }
});

// VIEW APPLICATIONS
app.get("/applications/:id",
  authMiddleware,
  roleMiddleware("admin"),
  async (req, res, next) => {
    try {
      const job = await Job.findById(req.params.id);
      if (!job) return res.status(404).json({ message: "Job not found" });

      res.json(job.applications);

    } catch (err) {
      next(err);
    }
  }
);

/* ================= ERROR HANDLER ================= */
app.use(errorHandler);

/* ================= START ================= */
app.listen(3000, () => {
  console.log("Server running on port 3000");
});