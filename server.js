
/**
 * Eco-Maktab.uz API
 * Node.js + Express + MongoDB
 */

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

if (!MONGODB_URI || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set MONGODB_URI and JWT_SECRET (at least 32 characters).");
  process.exit(1);
}

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "*" }));
app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 150 }));

const validRoles = ["school", "factory", "admin"];
const wasteTypes = ["plastic", "paper", "glass", "metal", "other"];
const orderStatuses = [
  "pending",
  "accepted",
  "pickup_reported",
  "completed",
  "rejected",
  "cancelled"
];

// ===============================
// ACCOUNT MODEL
// ===============================

const accountSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 120
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  passwordHash: {
    type: String,
    required: true,
    select: false
  },

  role: {
    type: String,
    enum: validRoles,
    required: true
  },

  region: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },

  address: {
    type: String,
    trim: true,
    maxlength: 300
  },

  phone: {
    type: String,
    trim: true,
    maxlength: 40
  },

  verificationStatus: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending"
  },

  verifiedFactories: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Account"
    }
  ],

  recyclingTypes: [
    {
      type: String,
      enum: wasteTypes
    }
  ],

  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Account = mongoose.model("Account", accountSchema);

// ===============================
// ORDER MODEL
// ===============================

const orderSchema = new mongoose.Schema({
  school: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Account",
    required: true
  },

  factory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Account",
    required: true
  },

  wasteType: {
    type: String,
    enum: wasteTypes,
    required: true
  },

  estimatedKg: {
    type: Number,
    required: true,
    min: 1,
    max: 1000000
  },

  schoolNotes: {
    type: String,
    trim: true,
    maxlength: 1000
  },

  pickupAddress: {
    type: String,
    required: true,
    trim: true,
    maxlength: 300
  },

  pickupRequestedAt: {
    type: Date,
    default: Date.now
  },

  status: {
    type: String,
    enum: orderStatuses,
    default: "pending"
  },

  acceptedAt: Date,

  actualKg: {
    type: Number,
    min: 0,
    max: 1000000
  },

  amountPaidUZS: {
    type: Number,
    min: 0,
    max: 100000000000
  },

  paymentReportedAt: Date,

  paymentReference: {
    type: String,
    trim: true,
    maxlength: 120
  },

  factoryEvidenceUrls: [
    {
      type: String,
      maxlength: 2000
    }
  ],

  schoolEvidenceUrls: [
    {
      type: String,
      maxlength: 2000
    }
  ],

  schoolApprovedAt: Date,
  completedAt: Date,

  rejectionReason: {
    type: String,
    trim: true,
    maxlength: 500
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  updatedAt: {
    type: Date,
    default: Date.now
  }
});

orderSchema.pre("save", function(next) {
  this.updatedAt = new Date();
  next();
});

const Order = mongoose.model("Order", orderSchema);

// ===============================
// AUTHENTICATION
// ===============================

function signToken(account) {
  return jwt.sign(
    {
      sub: account._id.toString(),
      role: account.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
      issuer: "eco-maktab.uz"
    }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required."
      });
    }

    const payload = jwt.verify(
      header.slice(7),
      JWT_SECRET,
      { issuer: "eco-maktab.uz" }
    );

    const account = await Account.findById(payload.sub);

    if (!account) {
      return res.status(401).json({
        error: "Account not found."
      });
    }

    req.account = account;
    next();

  } catch (e) {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.account || !roles.includes(req.account.role)) {
      return res.status(403).json({
        error: "You do not have permission."
      });
    }

    next();
  };
}

function requireApproved(req, res, next) {
  if (
    req.account.role !== "admin" &&
    req.account.verificationStatus !== "approved"
  ) {
    return res.status(403).json({
      error: "Your account must be approved first."
    });
  }

  next();
}

function validUrls(urls) {
  return (
    Array.isArray(urls) &&
    urls.length >= 1 &&
    urls.length <= 10 &&
    urls.every(
      (u) =>
        typeof u === "string" &&
        u.length <= 2000 &&
        /^https:\/\/.+/i.test(u)
    )
  );
}

// ===============================
// GENERAL ROUTES
// ===============================

app.get("/", (req, res) => {
  res.json({
    name: "Eco-Maktab.uz API",
    status: "running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

// ===============================
// REGISTRATION
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      role,
      region,
      address,
      phone,
      recyclingTypes
    } = req.body;

    if (!name || !email || !password || !role || !region) {
      return res.status(400).json({
        error: "name, email, password, role and region are required."
      });
    }

    if (!["school", "factory"].includes(role)) {
      return res.status(400).json({
        error: "Role must be school or factory."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Password must be 10–128 characters."
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    if (normalizedEmail === ADMIN_EMAIL && ADMIN_EMAIL) {
      return res.status(403).json({
        error: "This email is reserved for the administrator."
      });
    }

    if (await Account.findOne({ email: normalizedEmail })) {
      return res.status(409).json({
        error: "Email is already registered."
      });
    }

    const account = await Account.create({
      name,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
      role,
      region,
      address,
      phone,

      recyclingTypes:
        role === "factory" && Array.isArray(recyclingTypes)
          ? recyclingTypes.filter((t) => wasteTypes.includes(t))
          : [],

      verificationStatus: "pending"
    });

    return res.status(201).json({
      message: "Registration received. Your account is pending approval.",

      account: {
        id: account._id,
        name: account.name,
        email: account.email,
        role: account.role,
        verificationStatus: account.verificationStatus
      }
    });

  } catch (e) {
    return res.status(500).json({
      error: "Could not register account."
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = req.body.password;

    const account = await Account.findOne({ email })
      .select("+passwordHash");

    if (
      !account ||
      !(await bcrypt.compare(password || "", account.passwordHash))
    ) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    if (ADMIN_EMAIL && email === ADMIN_EMAIL && account.role !== "admin") {
      account.role = "admin";
      account.verificationStatus = "approved";
      await account.save();
    }

    return res.json({
      token: signToken(account),

      account: {
        id: account._id,
        name: account.name,
        email: account.email,
        role: account.role,
        region: account.region,
        verificationStatus: account.verificationStatus
      }
    });

  } catch (e) {
    return res.status(500).json({
      error: "Could not log in."
    });
  }
});

// ===============================
// ACCOUNT PROFILE
// ===============================

app.get("/api/account/me", auth, async (req, res) => {
  const a = req.account;

  res.json({
    id: a._id,
    name: a.name,
    email: a.email,
    role: a.role,
    region: a.region,
    address: a.address,
    phone: a.phone,
    verificationStatus: a.verificationStatus,
    verifiedFactories: a.verifiedFactories
  });
});

// ===============================
// ADMIN: ACCOUNTS
// ===============================

app.get(
  "/api/admin/accounts",
  auth,
  requireRole("admin"),
  async (req, res) => {

    const status = ["pending", "approved", "rejected"].includes(
      req.query.status
    )
      ? req.query.status
      : "pending";

    const accounts = await Account.find({
      role: { $in: ["school", "factory"] },
      verificationStatus: status
    })
      .select(
        "name email role region address phone verificationStatus recyclingTypes createdAt"
      )
      .sort({ createdAt: 1 });

    res.json(accounts);
  }
);

app.patch(
  "/api/admin/accounts/:id/verification",
  auth,
  requireRole("admin"),
  async (req, res) => {

    const { status } = req.body;

    if (!["approved", "rejected", "pending"].includes(status)) {
      return res.status(400).json({
        error: "Invalid status."
      });
    }

    const account = await Account.findById(req.params.id);

    if (!account || !["school", "factory"].includes(account.role)) {
      return res.status(404).json({
        error: "Account not found."
      });
    }

    account.verificationStatus = status;
    await account.save();

    res.json({
      message: "Account status updated.",
      id: account._id,
      verificationStatus: status
    });
  }
);

// ===============================
// SCHOOL VERIFIES FACTORY
// ===============================

app.post(
  "/api/schools/verify-factory/:factoryId",
  auth,
  requireRole("school"),
  requireApproved,
  async (req, res) => {

    const factory = await Account.findById(req.params.factoryId);

    if (
      !factory ||
      factory.role !== "factory" ||
      factory.verificationStatus !== "approved"
    ) {
      return res.status(404).json({
        error: "Approved factory not found."
      });
    }

    const already = req.account.verifiedFactories.some(
      (id) => id.toString() === factory._id.toString()
    );

    if (!already) {
      req.account.verifiedFactories.push(factory._id);
      await req.account.save();
    }

    res.json({
      message: "Factory verified by your school.",
      factoryId: factory._id
    });
  }
);

// ===============================
// FACTORY LIST
// ===============================

app.get(
  "/api/factories",
  auth,
  requireRole("school"),
  requireApproved,
  async (req, res) => {

    const filter = {
      role: "factory",
      verificationStatus: "approved"
    };

    if (req.query.region) {
      filter.region = String(req.query.region);
    }

    if (
      req.query.wasteType &&
      wasteTypes.includes(req.query.wasteType)
    ) {
      filter.recyclingTypes = req.query.wasteType;
    }

    const factories = await Account.find(filter)
      .select("name region address phone recyclingTypes");

    res.json(factories);
  }
);

// ===============================
// SCHOOL CREATES PICKUP ORDER
// ===============================

app.post(
  "/api/orders",
  auth,
  requireRole("school"),
  requireApproved,
  async (req, res) => {

    try {
      const {
        factoryId,
        wasteType,
        estimatedKg,
        pickupAddress,
        schoolNotes
      } = req.body;

      if (!factoryId || !wasteTypes.includes(wasteType) || !pickupAddress) {
        return res.status(400).json({
          error: "factoryId, wasteType and pickupAddress are required."
        });
      }

      const kg = Number(estimatedKg);

      if (!Number.isFinite(kg) || kg < 1 || kg > 1000000) {
        return res.status(400).json({
          error: "estimatedKg must be between 1 and 1,000,000."
        });
      }

      const factory = await Account.findOne({
        _id: factoryId,
        role: "factory",
        verificationStatus: "approved"
      });

      if (!factory) {
        return res.status(404).json({
          error: "Approved factory not found."
        });
      }

      if (
        !req.account.verifiedFactories.some(
          (id) => id.toString() === factory._id.toString()
        )
      ) {
        return res.status(403).json({
          error: "Your school must verify this factory before ordering."
        });
      }

      const order = await Order.create({
        school: req.account._id,
        factory: factory._id,
        wasteType,
        estimatedKg: kg,
        pickupAddress,
        schoolNotes
      });

      res.status(201).json(order);

    } catch (e) {
      res.status(500).json({
        error: "Could not create pickup order."
      });
    }
  }
);

// ===============================
// VIEW ORDERS
// ===============================

app.get("/api/orders", auth, async (req, res) => {

  const filter =
    req.account.role === "admin"
      ? {}
      : req.account.role === "school"
        ? { school: req.account._id }
        : { factory: req.account._id };

  const orders = await Order.find(filter)
    .populate("school", "name region")
    .populate("factory", "name region")
    .sort({ createdAt: -1 });

  res.json(orders);
});

// ===============================
// FACTORY ACCEPTS ORDER
// ===============================

app.patch(
  "/api/orders/:id/accept",
  auth,
  requireRole("factory"),
  requireApproved,
  async (req, res) => {

    const order = await Order.findOne({
      _id: req.params.id,
      factory: req.account._id,
      status: "pending"
    });

    if (!order) {
      return res.status(404).json({
        error: "Pending order not found for this factory."
      });
    }

    order.status = "accepted";
    order.acceptedAt = new Date();

    await order.save();

    res.json(order);
  }
);

// ===============================
// FACTORY REPORTS PICKUP + PAYMENT
// ===============================

app.patch(
  "/api/orders/:id/pickup-report",
  auth,
  requireRole("factory"),
  requireApproved,
  async (req, res) => {

    const order = await Order.findOne({
      _id: req.params.id,
      factory: req.account._id,
      status: "accepted"
    });

    if (!order) {
      return res.status(404).json({
        error: "Accepted order not found for this factory."
      });
    }

    const actualKg = Number(req.body.actualKg);
    const amountPaidUZS = Number(req.body.amountPaidUZS);
    const urls = req.body.factoryEvidenceUrls;

    if (
      !Number.isFinite(actualKg) ||
      actualKg <= 0 ||
      actualKg > 1000000
    ) {
      return res.status(400).json({
        error: "actualKg must be positive and <= 1,000,000."
      });
    }

    if (
      !Number.isFinite(amountPaidUZS) ||
      amountPaidUZS < 0 ||
      amountPaidUZS > 100000000000
    ) {
      return res.status(400).json({
        error: "Invalid amountPaidUZS."
      });
    }

    if (!validUrls(urls)) {
      return res.status(400).json({
        error: "Provide 1–10 HTTPS factoryEvidenceUrls."
      });
    }

    order.actualKg = actualKg;
    order.amountPaidUZS = Math.round(amountPaidUZS);

    order.paymentReference = String(
      req.body.paymentReference || ""
    ).slice(0, 120);

    order.factoryEvidenceUrls = urls;
    order.paymentReportedAt = new Date();
    order.status = "pickup_reported";

    await order.save();

    res.json({
      message: "Pickup and payment report saved. Waiting for school approval.",
      order
    });
  }
);

// ===============================
// SCHOOL APPROVES COLLECTION
// ===============================

app.patch(
  "/api/orders/:id/approve",
  auth,
  requireRole("school"),
  requireApproved,
  async (req, res) => {

    const order = await Order.findOne({
      _id: req.params.id,
      school: req.account._id,
      status: "pickup_reported"
    });

    if (!order) {
      return res.status(404).json({
        error: "Reported order not found for this school."
      });
    }

    const urls = req.body.schoolEvidenceUrls;

    if (!validUrls(urls)) {
      return res.status(400).json({
        error: "Provide 1–10 HTTPS schoolEvidenceUrls."
      });
    }

    order.schoolEvidenceUrls = urls;
    order.schoolApprovedAt = new Date();
    order.completedAt = new Date();
    order.status = "completed";

    await order.save();

    res.json({
      message: "Order approved and added to the leaderboard.",
      order
    });
  }
);

// ===============================
// SCHOOL REJECTS PAYMENT / REPORT
// ===============================

app.patch(
  "/api/orders/:id/reject-report",
  auth,
  requireRole("school"),
  requireApproved,
  async (req, res) => {

    const order = await Order.findOne({
      _id: req.params.id,
      school: req.account._id,
      status: "pickup_reported"
    });

    if (!order) {
      return res.status(404).json({
        error: "Reported order not found for this school."
      });
    }

    order.status = "rejected";

    order.rejectionReason = String(
      req.body.reason || "School disputed the report."
    ).slice(0, 500);

    await order.save();

    res.json({
      message: "Report rejected. Admin should help resolve the dispute.",
      order
    });
  }
);

// ===============================
// FACTORY REJECTS ORDER
// ===============================

app.patch(
  "/api/orders/:id/reject",
  auth,
  requireRole("factory"),
  requireApproved,
  async (req, res) => {

    const order = await Order.findOne({
      _id: req.params.id,
      factory: req.account._id,
      status: "pending"
    });

    if (!order) {
      return res.status(404).json({
        error: "Pending order not found for this factory."
      });
    }

    order.status = "rejected";

    order.rejectionReason = String(
      req.body.reason || "Factory declined the order."
    ).slice(0, 500);

    await order.save();

    res.json(order);
  }
);

// ===============================
// LEADERBOARD
// ===============================

app.get("/api/leaderboard", async (req, res) => {

  const rows = await Order.aggregate([
    {
      $match: {
        status: "completed",
        schoolApprovedAt: { $ne: null },
        actualKg: { $gt: 0 }
      }
    },

    {
      $group: {
        _id: "$school",
        totalKg: { $sum: "$actualKg" },
        completedPickups: { $sum: 1 }
      }
    },

    {
      $sort: {
        totalKg: -1
      }
    },

    {
      $limit: 100
    },

    {
      $lookup: {
        from: "accounts",
        localField: "_id",
        foreignField: "_id",
        as: "schoolInfo"
      }
    },

    {
      $unwind: "$schoolInfo"
    },

    {
      $project: {
        _id: 0,
        schoolId: "$_id",
        schoolName: "$schoolInfo.name",
        region: "$schoolInfo.region",
        totalKg: 1,
        completedPickups: 1
      }
    }
  ]);

  res.json(rows);
});

// ===============================
// ADMIN: VIEW ORDERS
// ===============================

app.get(
  "/api/admin/orders",
  auth,
  requireRole("admin"),
  async (req, res) => {

    const filter =
      req.query.status &&
      orderStatuses.includes(req.query.status)
        ? { status: req.query.status }
        : {};

    const orders = await Order.find(filter)
      .populate("school", "name region email")
      .populate("factory", "name region email")
      .sort({ updatedAt: -1 });

    res.json(orders);
  }
);

// ===============================
// ERROR HANDLING
// ===============================

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found."
  });
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Unexpected server error."
  });
});

// ===============================
// START SERVER
// ===============================

mongoose.connect(MONGODB_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Eco-Maktab API listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
