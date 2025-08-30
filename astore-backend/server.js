// server.js

// ────────────────────────────────
// IMPORTS & SETUP
// ────────────────────────────────
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const session = require("express-session");
const emailValidator = require("email-validator");
const dns = require("dns").promises;
const MongoStore = require("connect-mongo");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { body, query, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const multer = require("multer");
const { Parser } = require("json2csv");
const { randomUUID } = require("crypto");

dotenv.config();
const app = express();
app.set("trust proxy", 1); // for deployment

// ────────────────────────────────
// CORS
// ────────────────────────────────
const allowedOrigins = ["http://localhost:5173", process.env.FRONTEND_URL];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

// ────────────────────────────────
// BODY PARSE & COOKIES & SESSION
// ────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      ttl: 60 * 60 * 24 * 7,
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ────────────────────────────────
// GUEST ID COOKIE + INPUT SANITIZE
// ────────────────────────────────
app.use((req, res, next) => {
  if (req.headers.authorization?.startsWith("Bearer ")) return next();
  if (req.cookies?.guestId) return next();
  res.cookie("guestId", randomUUID(), { httpOnly: true, sameSite: "lax" });
  next();
});
const sanitizeInput = (req, res, next) => {
  const clean = (obj) => {
    Object.keys(obj).forEach((key) => {
      if (typeof obj[key] === "string")
        obj[key] = obj[key].replace(/[$][\w]+/g, "");
      else if (obj[key] && typeof obj[key] === "object") clean(obj[key]);
    });
  };
  if (req.body) clean(req.body);
  if (req.query) clean(req.query);
  if (req.params) clean(req.params);
  next();
};
app.use(sanitizeInput);

// ────────────────────────────────
//  FIREBASE ADMIN INITIALIZATION
// ────────────────────────────────

// Add to your imports section
const admin = require("firebase-admin");

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");

if (Object.keys(serviceAccount).length > 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  console.warn("Firebase Admin not initialized - missing service account");
}

// ────────────────────────────────
// DB SCHEMAS
// ────────────────────────────────

// USER
// USER SCHEMA (add avatar field)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: function () {
      // Password is only required for non-OAuth users
      return !this.oauthProvider;
    },
    select: false,
  },
  isAdmin: { type: Boolean, default: false },
  address: {
    street: String,
    city: String,
    country: String,
    postalCode: String,
  },
  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
  passwordResetToken: String,
  passwordResetExpires: Date,
  oauthProvider: String,
  oauthId: String,
  avatar: { type: String }, // Add this field for profile pictures
  isVerified: { type: Boolean, default: false }, // Add this field for email verification status
  createdAt: { type: Date, default: Date.now },
});

// Update the pre-save hook to handle OAuth users
userSchema.pre("save", async function (next) {
  // Only hash password if it's modified and user is not OAuth
  if (!this.isModified("password") || this.oauthProvider) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};
const User = mongoose.model("User", userSchema);

// CATEGORY
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
});
const Category = mongoose.model("Category", categorySchema);

// PRODUCT
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  discount: { type: Number, default: 0 },
  stock: { type: Number, required: true },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: true,
  },
  images: [{ type: String }],
  variantOptions: [
    {
      name: { type: String, required: true },
      values: [{ type: String, required: true }],
    },
  ],
  avgRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});
productSchema.pre("save", async function (next) {
  if (this.isModified("stock") && this.stock <= 5) {
    console.log(
      `Low stock alert: Product "${this.name}" has ${this.stock} units remaining.`
    );
  }
  next();
});
const Product = mongoose.model("Product", productSchema);

// REVIEW
const reviewSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String },
  verifiedPurchase: { type: Boolean, default: false },
  reactions: {
    helpful: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    funny: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    angry: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  adminReply: { message: { type: String }, date: { type: Date } },
  createdAt: { type: Date, default: Date.now },
});
const Review = mongoose.model("Review", reviewSchema);

// REACTION
const reactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  review: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Review",
    required: true,
  },
  type: { type: String, enum: ["helpful", "funny", "angry"], required: true },
  createdAt: { type: Date, default: Date.now },
});
reactionSchema.index({ user: 1, review: 1, type: 1 }, { unique: true });
const Reaction = mongoose.model("Reaction", reactionSchema);

// CART
const cartSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    unique: true,
    sparse: true,
  },
  guestId: { type: String, unique: true, sparse: true },
  items: [
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      quantity: { type: Number, required: true, min: 1 },
    },
  ],
  updatedAt: { type: Date, default: Date.now },
});
const Cart = mongoose.model("Cart", cartSchema);

// ORDER
const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true },
    },
  ],
  total: { type: Number, required: true },
  status: {
    type: String,
    enum: ["pending", "completed", "cancelled"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model("Order", orderSchema);

// ────────────────────────────────
// NODEMAILER TRANSPORTER
// ────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: process.env.EMAIL_SECURE === "true",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ────────────────────────────────
// DB CONNECT
// ────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("✖ DB connect error:", err));

// ────────────────────────────────
// AUTH MIDDLEWARES
// ────────────────────────────────
const authMiddleware = async (req, res, next) => {
  if (!req.session?.userId)
    return res.status(401).json({ error: "Not authenticated" });
  req.user = await User.findById(req.session.userId);
  if (!req.user) return res.status(401).json({ error: "User not found" });
  next();
};
const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin)
    return res.status(403).json({ error: "Admin required" });
  next();
};
const optionalAuth = async (req, res, next) => {
  if (req.session?.userId) req.user = await User.findById(req.session.userId);
  next();
};
const getCartQuery = (req) =>
  req.user ? { user: req.user._id } : { guestId: req.cookies.guestId };

// ────────────────────────────────
// RATE LIMITERS
// ────────────────────────────────
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 50 });
app.use("/api/users/login", authLimiter);

// ────────────────────────────────
// ROUTES: USERS
// ────────────────────────────────

// REGISTER

// REGISTER WITH EMAIL VALIDATION
app.post(
  "/api/users/register",
  [
    body("name").notEmpty(),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res, next) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

    try {
      const { name, email, password } = req.body;

      // Check if user already exists
      if (await User.findOne({ email })) {
        return res.status(400).json({ error: "Email already in use" });
      }

      // Validate email format
      if (!emailValidator.validate(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }

      // Check if email domain exists (basic validation)
      const domain = email.split("@")[1];
      try {
        await dns.resolveMx(domain);
      } catch (error) {
        return res
          .status(400)
          .json({
            error: "Email domain does not exist or cannot receive emails",
          });
      }

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString("hex");
      const verificationExpires = Date.now() + 24 * 60 * 60 * 1000;

      // Create user
      const user = new User({
        name,
        email,
        password,
        isVerified: false,
        verificationToken,
        verificationExpires,
      });

      await user.save();

      // Send verification email (try/catch in case email fails)
      try {
        const verificationUrl = `${
          process.env.FRONTEND_URL || "http://localhost:3000"
        }/verify-email/${verificationToken}`;

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Verify Your Email Address",
          html: `
            <h2>Email Verification</h2>
            <p>Hello ${name},</p>
            <p>Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
              Verify Email
            </a>
            <p>This link will expire in 24 hours.</p>
          `,
        });
      } catch (emailError) {
        console.error("Failed to send verification email:", emailError);
        // Continue with registration even if email fails
      }

      res.status(201).json({
        message:
          "Registration successful. Please check your email to verify your account.",
        requiresVerification: true,
      });
    } catch (e) {
      // Handle specific DNS validation errors
      if (e.code === "ENOTFOUND" || e.code === "ENODATA") {
        return res.status(400).json({ error: "Email domain does not exist" });
      }
      next(e);
    }
  }
);

// REGISTER WITH EMAIL VERIFICATION
app.post(
  "/api/users/register",
  [
    body("name").notEmpty(),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res, next) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

    try {
      const { name, email, password } = req.body;

      // Check if user already exists
      if (await User.findOne({ email }))
        return res.status(400).json({ error: "Email in use" });

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString("hex");
      const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      // Create user with verification fields
      const user = new User({
        name,
        email,
        password,
        isVerified: false,
        verificationToken,
        verificationExpires,
      });

      await user.save();

      // Send verification email
      try {
        const verificationUrl = `${
          process.env.FRONTEND_URL || "http://localhost:3000"
        }/verify-email/${verificationToken}`;

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Verify Your Email Address",
          html: `
            <h2>Email Verification</h2>
            <p>Hello ${name},</p>
            <p>Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
              Verify Email
            </a>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create this account, please ignore this email.</p>
          `,
        });
      } catch (emailError) {
        console.error("Failed to send verification email:", emailError);
        // Don't fail the registration if email fails, just log it
      }

      // Respond with success (but don't auto-login until verified)
      res.status(201).json({
        message:
          "Registration successful. Please check your email to verify your account.",
        requiresVerification: true,
      });
    } catch (e) {
      next(e);
    }
  }
);

// EMAIL VERIFICATION ENDPOINT
app.get("/api/users/verify-email/:token", async (req, res, next) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Invalid or expired verification token" });
    }

    // Mark user as verified and clear verification fields
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    // Auto-login after successful verification
    req.session.userId = user._id;
    req.session.save((err) => {
      if (err) return next(err);
      const safeUser = { ...user.toObject(), password: undefined };
      res.json({
        message: "Email verified successfully!",
        user: safeUser,
      });
    });
  } catch (error) {
    next(error);
  }
});

// RESEND VERIFICATION EMAIL ENDPOINT
app.post("/api/users/resend-verification", async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email, isVerified: false });

    if (!user) {
      return res
        .status(400)
        .json({ error: "User not found or already verified" });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationExpires = Date.now() + 24 * 60 * 60 * 1000;

    user.verificationToken = verificationToken;
    user.verificationExpires = verificationExpires;
    await user.save();

    // Send new verification email
    const verificationUrl = `${
      process.env.FRONTEND_URL || "http://localhost:3000"
    }/verify-email/${verificationToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email Address",
      html: `
        <h2>Email Verification</h2>
        <p>Hello ${user.name},</p>
        <p>Here's your new verification link:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Verify Email
        </a>
        <p>This link will expire in 24 hours.</p>
      `,
    });

    res.json({ message: "Verification email sent successfully" });
  } catch (error) {
    next(error);
  }
});

// LOGIN (update to handle OAuth users)
app.post(
  "/api/users/login",
  [body("email").isEmail(), body("password").notEmpty()],
  async (req, res, next) => {
    const errs = validationResult(req);
    if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email }).select("+password");

      if (!user) return res.status(400).json({ error: "Invalid credentials" });

      // Check if user registered with OAuth
      if (user.oauthProvider) {
        return res.status(400).json({
          error: `This account was created with ${user.oauthProvider}. Please use ${user.oauthProvider} login.`,
        });
      }

      if (!(await bcrypt.compare(password, user.password)))
        return res.status(400).json({ error: "Invalid credentials" });

      req.session.userId = user._id;
      req.session.save(async (err) => {
        if (err) return next(err);
        const safeUser = await User.findById(user._id).select("-password");
        res.json({ user: safeUser });
      });
    } catch (e) {
      next(e);
    }
  }
);
// CHECK LOGIN METHOD
app.get("/api/users/check-login-method/:email", async (req, res, next) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.json({ exists: false });
    }

    res.json({
      exists: true,
      oauthProvider: user.oauthProvider || null,
      hasPassword: !user.oauthProvider, // If no OAuth provider, they have a password
    });
  } catch (error) {
    next(error);
  }
});
// LOGOUT
app.post("/api/users/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

// PROFILE
app.get("/api/users/profile", authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select("-password");
    res.json(user);
  } catch (e) {
    next(e);
  }
});

// UPDATE PROFILE
app.put(
  "/api/users/profile",
  authMiddleware,
  [
    body("name").optional().notEmpty().withMessage("Name cannot be empty"),
    body("email").optional().isEmail().withMessage("Valid email is required"),
    body("address.street").optional().trim(),
    body("address.city").optional().trim(),
    body("address.country").optional().trim(),
    body("address.postalCode").optional().trim(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { name, email, address } = req.body;
      const updateData = {};
      if (name) updateData.name = name;
      if (email) {
        const existingUser = await User.findOne({
          email,
          _id: { $ne: req.user._id },
        });
        if (existingUser)
          return res.status(400).json({ error: "Email already exists" });
        updateData.email = email;
      }
      if (address) updateData.address = address;

      const user = await User.findByIdAndUpdate(req.user._id, updateData, {
        new: true,
      }).select("-password");
      res.json({ message: "Profile updated", user });
    } catch (error) {
      next(error);
    }
  }
);

// UPDATE PASSWORD
app.put(
  "/api/users/password",
  authMiddleware,
  [
    body("currentPassword")
      .notEmpty()
      .withMessage("Current password is required"),
    body("newPassword")
      .isLength({ min: 6 })
      .withMessage("New password must be at least 6 characters"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user._id).select("+password");
      if (!user) return res.status(404).json({ error: "User not found" });

      const match = await bcrypt.compare(
        req.body.currentPassword,
        user.password
      );
      if (!match)
        return res.status(400).json({ error: "Current password is incorrect" });

      user.password = await bcrypt.hash(req.body.newPassword, 10);
      await user.save();

      res.json({ message: "Password updated successfully" });
    } catch (err) {
      next(err);
    }
  }
);

// GET ALL USERS (ADMIN ONLY)
app.get(
  "/api/users",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const users = await User.find({})
        .sort({ createdAt: -1 })
        .select("-password");
      res.json(users);
    } catch (err) {
      next(err);
    }
  }
);

// GOOGLE LOGIN ENDPOINT
app.post("/api/users/google-login", async (req, res, next) => {
  try {
    const { uid, email, name, photoURL } = req.body;

    // Validate required fields
    if (!uid || !email) {
      return res
        .status(400)
        .json({ error: "Missing required authentication data" });
    }

    // Find user by oauthId (Firebase UID) or email
    let user = await User.findOne({
      $or: [
        { oauthId: uid, oauthProvider: "google" },
        { email: email.toLowerCase() },
      ],
    });

    if (user) {
      // If user exists by email but doesn't have oauth setup
      if (!user.oauthId || user.oauthProvider !== "google") {
        user.oauthId = uid;
        user.oauthProvider = "google";

        // Update name and photo if not set
        if (name && !user.name) user.name = name;
        if (photoURL && !user.avatar) user.avatar = photoURL;

        await user.save();
      } else {
        // Update profile information if needed
        const updates = {};
        if (name && user.name !== name) updates.name = name;
        if (photoURL && !user.avatar) updates.avatar = photoURL;

        if (Object.keys(updates).length > 0) {
          await User.findByIdAndUpdate(user._id, updates);
        }
      }
    } else {
      // Create new user with Google authentication
      user = new User({
        name: name || email.split("@")[0],
        email: email.toLowerCase(),
        oauthId: uid,
        oauthProvider: "google",
        avatar: photoURL || "",
        isVerified: true,
        // Generate a random password for security (won't be used for OAuth users)
        password: crypto.randomBytes(16).toString("hex"),
      });
      await user.save();
    }

    // Set session
    req.session.userId = user._id;

    // Return user data (excluding password)
    const userResponse = await User.findById(user._id).select("-password");
    res.json({
      user: userResponse,
      message: "Google authentication successful",
    });
  } catch (error) {
    console.error("Google login error:", error);

    // Handle duplicate email error
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(400).json({
        error: "Email already exists with a different login method",
      });
    }

    res.status(500).json({ error: "Authentication failed" });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: CATEGORIES (CRUD, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  "/api/categories",
  authMiddleware,
  adminMiddleware,
  [body("name").notEmpty().withMessage("Name is required")],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { name, description } = req.body;
      const existing = await Category.findOne({ name: name.trim() });
      if (existing)
        return res.status(400).json({ error: "Category already exists" });

      const category = new Category({ name: name.trim(), description });
      await category.save();
      res.status(201).json(category);
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/categories", async (req, res, next) => {
  try {
    const categories = await Category.find().sort({ name: 1 });
    res.json(categories);
  } catch (err) {
    next(err);
  }
});

app.put(
  "/api/categories/:id",
  authMiddleware,
  adminMiddleware,
  [body("name").notEmpty().withMessage("Name is required")],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const category = await Category.findById(req.params.id);
      if (!category)
        return res.status(404).json({ error: "Category not found" });

      category.name = req.body.name.trim();
      category.description = req.body.description || "";
      await category.save();
      res.json(category);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/categories/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const category = await Category.findByIdAndDelete(req.params.id);
      if (!category)
        return res.status(404).json({ error: "Category not found" });
      res.json({ message: "Category deleted" });
    } catch (err) {
      next(err);
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: PRODUCTS (CRUD, SEARCH + PAGINATION, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  "/api/products",
  authMiddleware,
  adminMiddleware,
  [
    body("name").notEmpty().withMessage("Product name is required"),
    body("price")
      .isFloat({ min: 0 })
      .withMessage("Price must be a positive number"),
    body("stock")
      .isInt({ min: 0 })
      .withMessage("Stock must be a non-negative integer"),
    body("category").notEmpty().withMessage("Category ID is required"),
    body("discount")
      .optional()
      .isFloat({ min: 0, max: 100 })
      .withMessage("Discount must be between 0 and 100"),
    body("images")
      .optional()
      .isArray()
      .withMessage("Images must be an array of URLs"),
    body("images.*")
      .optional()
      .isURL()
      .withMessage("Each image must be a valid URL"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { name, description, price, stock, category, discount, images } =
        req.body;
      const categoryExists = await Category.findById(category);
      if (!categoryExists)
        return res.status(400).json({ error: "Invalid category ID" });

      const product = new Product({
        name,
        description,
        price,
        stock,
        category,
        discount,
        images,
      });
      await product.save();
      res.status(201).json({ message: "Product created", product });
    } catch (error) {
      next(error);
    }
  }
);

app.delete(
  "/api/products/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const deleted = await Product.findByIdAndDelete(req.params.id);
      if (!deleted) return res.status(404).json({ error: "Product not found" });
      res.json({ message: "Product deleted" });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  "/api/products/:id",
  authMiddleware,
  adminMiddleware,
  [
    body("name").optional().notEmpty(),
    body("price").optional().isFloat({ min: 0 }),
    body("stock").optional().isInt({ min: 0 }),
    body("discount").optional().isFloat({ min: 0, max: 100 }),
    body("images").optional().isArray(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const updated = await Product.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
      });
      if (!updated) return res.status(404).json({ error: "Product not found" });
      res.json({ message: "Product updated", product: updated });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/products (search, filters, pagination, rating aggregation)
app.get(
  "/api/products",
  [
    query("search").optional().trim(),
    query("category").optional().trim(),
    query("minPrice").optional().isFloat({ min: 0 }),
    query("maxPrice").optional().isFloat({ min: 0 }),
    query("page").optional().isInt({ min: 1 }),
    query("limit").optional().isInt({ min: 1 }),
    query("discounted").optional().isBoolean(),
    query("inStock").optional().isBoolean(),
    query("sort").optional().isString(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const {
        search,
        category,
        minPrice,
        maxPrice,
        page = 1,
        limit = 10,
        discounted,
        inStock,
        sort,
      } = req.query;

      const queryObj = {};

      if (search) {
        queryObj.name = { $regex: search, $options: "i" };
      }
      if (category) {
        queryObj.category = category;
      }
      if (minPrice || maxPrice) {
        queryObj.price = {};
        if (minPrice) queryObj.price.$gte = parseFloat(minPrice);
        if (maxPrice) queryObj.price.$lte = parseFloat(maxPrice);
      }
      if (discounted === "true") {
        queryObj.discount = { $gt: 0 };
      }
      if (inStock === "true") {
        queryObj.stock = { $gt: 0 };
      }

      const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

      // Sorting options
      const sortOptions = {
        price_asc: { price: 1 },
        price_desc: { price: -1 },
        rating_desc: { avgRating: -1 }, // will adjust in JS
        newest: { createdAt: -1 },
      };
      const sortQuery = sortOptions[sort] || { createdAt: -1 };

      const products = await Product.find(queryObj)
        .populate("category")
        .sort(sortQuery)
        .skip(skip)
        .limit(parseInt(limit, 10));

      const total = await Product.countDocuments(queryObj);
      const productIds = products.map((p) => p._id);

      // Aggregate ratings
      const ratings = await Review.aggregate([
        { $match: { product: { $in: productIds } } },
        {
          $group: {
            _id: "$product",
            avgRating: { $avg: "$rating" },
            totalReviews: { $sum: 1 },
          },
        },
      ]);

      const ratingMap = {};
      ratings.forEach((r) => {
        ratingMap[r._id.toString()] = {
          avgRating: Math.round(r.avgRating * 10) / 10,
          totalReviews: r.totalReviews,
        };
      });

      let productsWithRatings = products.map((p) => {
        const { avgRating = 0, totalReviews = 0 } =
          ratingMap[p._id.toString()] || {};
        return {
          ...p.toObject(),
          avgRating,
          totalReviews,
        };
      });

      // If sorting by rating, do it here
      if (sort === "rating_desc") {
        productsWithRatings = productsWithRatings.sort(
          (a, b) => b.avgRating - a.avgRating
        );
      }

      res.json({
        products: productsWithRatings,
        totalPages: Math.ceil(total / parseInt(limit, 10)),
        currentPage: parseInt(page, 10),
      });
    } catch (error) {
      next(error);
    }
  }
);

// GET /api/products/:id (with rating)
app.get("/api/products/:id", async (req, res, next) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) {
    return res.status(400).json({ error: "Invalid product ID format." });
  }

  try {
    const product = await Product.findById(id).populate("category");
    if (!product) {
      return res.status(404).json({ error: "Product not found." });
    }

    const [ratingStats] = await Review.aggregate([
      { $match: { product: product._id } },
      {
        $group: {
          _id: null,
          avgRating: { $avg: "$rating" },
          totalReviews: { $sum: 1 },
        },
      },
    ]);

    const avgRating = ratingStats?.avgRating || 0;
    const totalReviews = ratingStats?.totalReviews || 0;

    return res.json({
      ...product.toObject(),
      avgRating: Math.round(avgRating * 10) / 10,
      totalReviews,
    });
  } catch (err) {
    console.error("Error in GET /api/products/:id →", err.message);
    console.error(err.stack);
    return res
      .status(500)
      .json({ error: "Server error. Please try again later." });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: REVIEWS (CRUD, REACTIONS, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  "/api/reviews",
  authMiddleware,
  [
    body("productId").notEmpty().withMessage("Product ID is required"),
    body("rating")
      .isInt({ min: 1, max: 5 })
      .withMessage("Rating must be between 1 and 5"),
    body("comment").optional().trim(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { productId, rating, comment } = req.body;
      const product = await Product.findById(productId);
      if (!product) return res.status(400).json({ error: "Product not found" });

      const existing = await Review.findOne({
        user: req.user._id,
        product: productId,
      });
      if (existing)
        return res
          .status(400)
          .json({ error: "You have already reviewed this product" });

      const hasOrdered = await Order.exists({
        user: req.user._id,
        "items.product": productId,
      });

      const review = new Review({
        user: req.user._id,
        product: productId,
        rating,
        comment,
        verifiedPurchase: !!hasOrdered,
      });

      await review.save();
      res.status(201).json({ message: "Review added", review });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/api/products/:id/reviews",
  authMiddleware,
  [
    body("rating")
      .isInt({ min: 1, max: 5 })
      .withMessage("Rating must be between 1 and 5"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const product = await Product.findById(req.params.id);
      if (!product) return res.status(404).json({ error: "Product not found" });

      const existing = await Review.findOne({
        user: req.user._id,
        product: product._id,
      });
      if (existing) {
        return res
          .status(400)
          .json({ error: "You have already reviewed this product" });
      }

      const { rating, comment } = req.body;
      const review = new Review({
        user: req.user._id,
        product: product._id,
        rating,
        comment,
        verifiedPurchase: false,
      });
      await review.save();

      res.status(201).json({ message: "Review added", review });
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/reviews/:productId", optionalAuth, async (req, res, next) => {
  try {
    const reviews = await Review.find({
      product: req.params.productId,
    }).populate("user", "name");
    const userId = req.user?._id?.toString();

    const enriched = reviews.map((review) => {
      const reviewObj = review.toObject();
      if (userId) {
        const found = review.reactions?.helpful.find(
          (u) => u.toString() === userId
        )
          ? "helpful"
          : review.reactions?.funny.find((u) => u.toString() === userId)
          ? "funny"
          : review.reactions?.angry.find((u) => u.toString() === userId)
          ? "angry"
          : null;
        reviewObj.userReactionType = found;
      }
      return reviewObj;
    });

    res.json(enriched);
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/reviews/:id",
  authMiddleware,
  [body("rating").isInt({ min: 1, max: 5 }).withMessage("Rating 1–5 required")],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const review = await Review.findById(req.params.id);
      if (!review) return res.status(404).json({ error: "Review not found" });

      if (!review.user.equals(req.user._id))
        return res.status(403).json({ error: "Not allowed" });

      review.rating = req.body.rating;
      review.comment = req.body.comment;
      await review.save();
      res.json({ message: "Review updated", review });
    } catch (err) {
      next(err);
    }
  }
);

app.delete("/api/reviews/:id", authMiddleware, async (req, res, next) => {
  try {
    const review = await Review.findById(req.params.id);
    if (!review) {
      return res.status(404).json({ error: "Review not found" });
    }

    if (!review.user.equals(req.user._id) && req.user.isAdmin !== true) {
      return res.status(403).json({ error: "Not allowed" });
    }

    await review.deleteOne();
    res.json({ message: "Review deleted" });
  } catch (err) {
    next(err);
  }
});

app.post("/api/reviews/:id/react", authMiddleware, async (req, res) => {
  try {
    const { type } = req.body;
    const validTypes = ["helpful", "funny", "angry"];
    if (!validTypes.includes(type))
      return res.status(400).json({ error: "Invalid reaction type" });

    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ error: "Review not found" });

    const userId = req.user._id.toString();
    const alreadyReacted = review.reactions[type]
      ?.map((u) => u.toString())
      .includes(userId);

    if (alreadyReacted) {
      review.reactions[type] = review.reactions[type].filter(
        (u) => u.toString() !== userId
      );
    } else {
      review.reactions[type] = [
        ...(review.reactions[type] || []),
        req.user._id,
      ];
    }

    await review.save();
    res.json({ message: "Reaction updated", reactions: review.reactions });
  } catch (err) {
    res.status(500).json({ error: "Failed to react" });
  }
});

// Admin‐only: List all reviews
app.get(
  "/api/reviews",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const allReviews = await Review.find()
        .populate("user", "name")
        .populate("product", "name");
      res.json(allReviews);
    } catch (err) {
      next(err);
    }
  }
);

// Admin replies to a review
app.post(
  "/api/reviews/reply/:id",
  authMiddleware,
  adminMiddleware,
  [body("reply").notEmpty().withMessage("Reply cannot be empty")],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const review = await Review.findById(req.params.id);
      if (!review) return res.status(404).json({ error: "Review not found" });

      review.adminReply = {
        message: req.body.reply,
        date: Date.now(),
      };
      await review.save();
      res.json({ message: "Reply added", review });
    } catch (err) {
      next(err);
    }
  }
);

app.get("/api/reactions/:productId", authMiddleware, async (req, res, next) => {
  try {
    const reviews = await Review.find({ product: req.params.productId }).lean();
    const result = {};
    for (const r of reviews) {
      const helpfulCount = r.reactions.helpful?.length || 0;
      const funnyCount = r.reactions.funny?.length || 0;
      const angryCount = r.reactions.angry?.length || 0;
      const userReactedType = r.reactions.helpful
        .map((u) => u.toString())
        .includes(req.user._id.toString())
        ? "helpful"
        : r.reactions.funny
            .map((u) => u.toString())
            .includes(req.user._id.toString())
        ? "funny"
        : r.reactions.angry
            .map((u) => u.toString())
            .includes(req.user._id.toString())
        ? "angry"
        : null;

      result[r._id] = {
        helpful: helpfulCount,
        funny: funnyCount,
        angry: angryCount,
        userReactionType: userReactedType,
      };
    }
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Alternative endpoint for adding a reaction record to the Reaction model
app.post("/api/reactions", authMiddleware, async (req, res, next) => {
  try {
    const { reviewId, type } = req.body;
    if (!["helpful", "funny", "angry"].includes(type)) {
      return res.status(400).json({ error: "Invalid reaction type" });
    }

    const existing = await Reaction.findOne({
      user: req.user._id,
      review: reviewId,
      type,
    });
    if (existing) {
      return res.status(400).json({ error: "Already reacted" });
    }

    const reaction = new Reaction({
      user: req.user._id,
      review: reviewId,
      type,
    });
    await reaction.save();
    res.json({ message: "Reaction added" });
  } catch (err) {
    next(err);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: CART (support guest via guestId)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  "/api/cart",
  optionalAuth,
  [
    body("productId").notEmpty().withMessage("Product ID is required"),
    body("quantity")
      .isInt({ min: 1 })
      .withMessage("Quantity must be at least 1"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { productId, quantity } = req.body;
      const product = await Product.findById(productId);
      if (!product) return res.status(400).json({ error: "Product not found" });
      if (product.stock < quantity)
        return res.status(400).json({ error: "Insufficient stock" });

      const query = getCartQuery(req);
      let cart = await Cart.findOne(query);
      if (!cart) {
        cart = new Cart({ ...query, items: [] });
      }

      const existingItemIndex = cart.items.findIndex(
        (item) => item.product.toString() === productId
      );
      if (existingItemIndex > -1) {
        cart.items[existingItemIndex].quantity += quantity;
      } else {
        cart.items.push({ product: productId, quantity });
      }
      cart.updatedAt = Date.now();
      await cart.save();

      const populatedCart = await cart.populate("items.product");
      res.json({ message: "Cart updated", cart: populatedCart });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/cart", optionalAuth, async (req, res, next) => {
  try {
    const query = getCartQuery(req);
    let cart = await Cart.findOne(query).populate("items.product");
    if (!cart) return res.json({ items: [] });
    res.json(cart);
  } catch (error) {
    next(error);
  }
});

app.delete("/api/cart/:productId", optionalAuth, async (req, res, next) => {
  try {
    const query = getCartQuery(req);
    const cart = await Cart.findOne(query);
    if (!cart) return res.status(404).json({ error: "Cart not found" });

    cart.items = cart.items.filter(
      (item) => item.product.toString() !== req.params.productId
    );
    cart.updatedAt = Date.now();
    await cart.save();

    const populatedCart = await cart.populate("items.product");
    res.json({ message: "Item removed from cart", cart: populatedCart });
  } catch (error) {
    next(error);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: ORDERS
// ────────────────────────────────────────────────────────────────────────────────

app.post("/api/orders", authMiddleware, async (req, res, next) => {
  try {
    const { items, shippingAddress, paymentMethod } = req.body;
    if (!items || items.length === 0)
      return res.status(400).json({ error: "No items in order" });

    const order = new Order({
      user: req.user._id,
      items: items.map((i) => ({
        product: i.productId,
        quantity: i.quantity,
        price: i.price,
      })),
      shippingAddress,
      paymentMethod,
      total: items.reduce((acc, i) => acc + i.price * i.quantity, 0),
      status: "pending",
    });
    await order.save();

    // Reduce stock
    for (let i of items) {
      await Product.findByIdAndUpdate(i.productId, {
        $inc: { stock: -i.quantity },
      });
    }

    res.status(201).json(order);
  } catch (err) {
    next(err);
  }
});

app.get("/api/orders/my", authMiddleware, async (req, res, next) => {
  try {
    const orders = await Order.find({ user: req.user._id }).sort({
      createdAt: -1,
    });
    res.json(orders);
  } catch (err) {
    next(err);
  }
});

app.get("/api/orders/:id", authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate("user", "name email")
      .populate("items.product", "name price");
    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json(order);
  } catch (err) {
    next(err);
  }
});

app.put("/api/orders/:id/pay", authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found" });

    order.isPaid = true;
    order.paidAt = Date.now();
    order.paymentResult = {
      id: req.body.id,
      status: req.body.status,
      update_time: req.body.update_time,
      email_address: req.body.payer.email_address,
    };
    await order.save();
    res.json(order);
  } catch (err) {
    next(err);
  }
});

app.get("/api/orders", authMiddleware, async (req, res, next) => {
  try {
    const orders = await Order.find({ user: req.user._id }).populate(
      "items.product"
    );
    res.json(orders);
  } catch (error) {
    next(error);
  }
});

app.put(
  "/api/orders/:orderId/cancel",
  authMiddleware,
  async (req, res, next) => {
    try {
      const order = await Order.findById(req.params.orderId);
      if (!order) return res.status(404).json({ error: "Order not found" });
      if (order.user.toString() !== req.user._id.toString())
        return res
          .status(403)
          .json({ error: "Not authorized to cancel this order" });
      if (order.status !== "pending")
        return res
          .status(400)
          .json({ error: "Only pending orders can be cancelled" });

      order.status = "cancelled";
      // Restore stock
      for (const item of order.items) {
        await Product.findByIdAndUpdate(item.product, {
          $inc: { stock: item.quantity },
        });
      }
      await order.save();
      res.json({ message: "Order cancelled", order });
    } catch (error) {
      next(error);
    }
  }
);

app.delete("/api/orders/:id", authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found" });
    if (order.user.toString() !== req.user._id.toString())
      return res.status(403).json({ error: "Not authorized" });
    await order.deleteOne();
    res.json({ message: "Order deleted" });
  } catch (err) {
    next(err);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ADMIN: ORDERS, USER MANAGEMENT, ANALYTICS, EXPORT/IMPORT
// ────────────────────────────────────────────────────────────────────────────────

// Admin: Get All Orders (most recent first, with products)
app.get(
  "/api/admin/orders",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 20;
      const sort = { createdAt: -1 };
      const orders = await Order.find({})
        .sort(sort)
        .limit(limit)
        .populate("user", "name email")
        .populate("items.product", "name price")
        .lean();
      res.json(orders);
    } catch (err) {
      next(err);
    }
  }
);

// Admin: Delete Any Order
app.delete(
  "/api/admin/orders/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const order = await Order.findById(req.params.id);
      if (!order) return res.status(404).json({ error: "Order not found" });
      await order.deleteOne();
      res.json({ message: "Order deleted" });
    } catch (err) {
      next(err);
    }
  }
);

// Admin: Update Order Status
app.put(
  "/api/admin/orders/:orderId",
  authMiddleware,
  adminMiddleware,
  [
    body("status")
      .isIn(["pending", "completed", "cancelled"])
      .withMessage("Invalid status"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const { status } = req.body;
      const order = await Order.findById(req.params.orderId);
      if (!order) return res.status(404).json({ error: "Order not found" });

      order.status = status;
      await order.save();
      res.json({ message: "Order status updated", order });
    } catch (error) {
      next(error);
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────────
// ADMIN ANALYTICS ROUTES
// ────────────────────────────────────────────────────────────────────────────────

app.get(
  "/api/admin/analytics/sales",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const match = { status: "completed" };
      if (start || end) {
        match.createdAt = {};
        if (start) match.createdAt.$gte = new Date(start);
        if (end) match.createdAt.$lte = new Date(end);
      }

      const daily = await Order.aggregate([
        { $match: match },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            totalSales: { $sum: "$total" },
          },
        },
        { $sort: { _id: 1 } },
        {
          $project: {
            _id: 0,
            date: "$_id",
            totalSales: 1,
          },
        },
      ]);

      res.json(daily);
    } catch (error) {
      res.status(500).json({ error: "Failed to get sales timeseries" });
    }
  }
);

app.get(
  "/api/admin/analytics/top-products",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const match = { status: "completed" };
      if (start || end) {
        match.createdAt = {};
        if (start) match.createdAt.$gte = new Date(start);
        if (end) match.createdAt.$lte = new Date(end);
      }

      const topProducts = await Order.aggregate([
        { $match: match },
        { $unwind: "$items" },
        {
          $group: {
            _id: "$items.product",
            totalQuantity: { $sum: "$items.quantity" },
            totalRevenue: {
              $sum: { $multiply: ["$items.quantity", "$items.price"] },
            },
          },
        },
        {
          $lookup: {
            from: "products",
            localField: "_id",
            foreignField: "_id",
            as: "product",
          },
        },
        { $unwind: "$product" },
        {
          $project: {
            name: "$product.name",
            totalQuantity: 1,
            totalRevenue: 1,
          },
        },
        { $sort: { totalQuantity: -1 } },
        { $limit: 5 },
      ]);

      res.json(topProducts);
    } catch (error) {
      res.status(500).json({ error: "Failed to get top products" });
    }
  }
);

app.get(
  "/api/admin/analytics/category-sales",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const categorySales = await Order.aggregate([
        { $match: { status: "completed" } },
        { $unwind: "$items" },
        {
          $lookup: {
            from: "products",
            localField: "items.product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        { $unwind: "$productInfo" },
        {
          $lookup: {
            from: "categories",
            localField: "productInfo.category",
            foreignField: "_id",
            as: "categoryInfo",
          },
        },
        { $unwind: "$categoryInfo" },
        {
          $group: {
            _id: "$categoryInfo.name",
            totalRevenue: {
              $sum: { $multiply: ["$items.price", "$items.quantity"] },
            },
          },
        },
        { $sort: { totalRevenue: -1 } },
      ]);

      res.json(categorySales);
    } catch (error) {
      res.status(500).json({ error: "Failed to get category sales" });
    }
  }
);

app.get(
  "/api/admin/analytics/counts",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const userCount = await User.countDocuments({ isAdmin: false });
      const productCount = await Product.countDocuments();
      const orderCount = await Order.countDocuments();
      const reviewCount = await Review.countDocuments();

      res.json({
        users: userCount,
        products: productCount,
        orders: orderCount,
        reviews: reviewCount,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to get counts" });
    }
  }
);

app.get(
  "/api/admin/analytics/top-customers",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 5;
      const customers = await Order.aggregate([
        { $match: { status: "completed" } },
        {
          $group: {
            _id: "$user",
            totalSpent: { $sum: "$total" },
          },
        },
        {
          $lookup: {
            from: "users",
            localField: "_id",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        { $unwind: "$userInfo" },
        {
          $project: {
            _id: 1,
            name: "$userInfo.name",
            totalSpent: 1,
          },
        },
        { $sort: { totalSpent: -1 } },
        { $limit: limit },
      ]);

      res.json({ customers });
    } catch (error) {
      res.status(500).json({ error: "Failed to get top customers" });
    }
  }
);

app.get(
  "/api/admin/analytics/low-stock",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const threshold = parseInt(req.query.threshold, 10) || 5;
      const products = await Product.find({ stock: { $lte: threshold } })
        .select("_id name stock")
        .lean();

      const results = products.map((p) => ({
        _id: p._id,
        name: p.name,
        countInStock: p.stock,
      }));

      res.json({ products: results });
    } catch (error) {
      res.status(500).json({ error: "Failed to get low-stock products" });
    }
  }
);

// Admin User Management (toggle isAdmin, delete user)
app.put(
  "/api/users/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      if (typeof req.body.isAdmin === "boolean") {
        user.isAdmin = req.body.isAdmin;
      }
      await user.save();
      res.json(user);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/api/users/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json({ message: "User deleted" });
    } catch (err) {
      next(err);
    }
  }
);

// ────────────────────────────────
// ERROR HANDLING & SERVER START
// ────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🗝 Server running on port ${PORT}`));
