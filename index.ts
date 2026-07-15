import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import cors from "cors";
import dns from "dns";
import dotenv from "dotenv";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { OAuth2Client } from "google-auth-library";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import mongoose, { Schema } from "mongoose";
import Stripe from "stripe";
import { z } from "zod";

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 5000;
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";
const cookieName = process.env.COOKIE_NAME || "sharebari_token";
const cookieMaxAgeDays = Number(process.env.COOKIE_MAX_AGE_DAYS) || 7;
const bcryptSaltRounds = Number(process.env.BCRYPT_SALT_ROUNDS) || 12;
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "7d";
const stripeCurrency = process.env.STRIPE_CURRENCY || "bdt";
const isProduction = process.env.NODE_ENV === "production";
const dnsServers = (process.env.DNS_SERVERS || (!isProduction ? "8.8.8.8,1.1.1.1" : ""))
  .split(",")
  .map((server) => server.trim())
  .filter(Boolean);
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;
let mongoConnectionPromise: Promise<typeof mongoose> | null = null;

if (dnsServers.length > 0) {
  dns.setServers(dnsServers);
}

type ItemCategory =
  | "tools-equipment"
  | "cameras-electronics"
  | "event-party"
  | "outdoor-sports"
  | "home-kitchen"
  | "books-learning";

type JwtPayload = {
  userId: string;
  email: string;
  role: UserRole;
};

type AuthRequest = Request & {
  user?: JwtPayload;
};

type UserRole = "user" | "admin";

const itemCategories: ItemCategory[] = [
  "tools-equipment",
  "cameras-electronics",
  "event-party",
  "outdoor-sports",
  "home-kitchen",
  "books-learning",
];
const conditions = ["like-new", "excellent", "good", "fair"] as const;
const availabilities = ["available", "rented", "unavailable"] as const;
const userRoles = ["user", "admin"] as const;
const adminEmails = (process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true },
    location: { type: String, trim: true },
    password: { type: String, select: false },
    googleId: { type: String },
    authProvider: { type: String, enum: ["local", "google"], required: true, default: "local" },
    role: { type: String, enum: userRoles, required: true, default: "user" },
    avatar: { type: String },
  },
  { timestamps: true },
);

const rentalItemSchema = new Schema(
  {
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true },
    shortDescription: { type: String, required: true, trim: true },
    fullDescription: { type: String, required: true, trim: true },
    category: { type: String, enum: itemCategories, required: true },
    dailyPrice: { type: Number, required: true, min: 1 },
    securityDeposit: { type: Number, required: true, min: 0 },
    location: { type: String, required: true, trim: true },
    condition: { type: String, enum: conditions, required: true },
    availability: { type: String, enum: availabilities, required: true, default: "available" },
    brand: { type: String, trim: true },
    model: { type: String, trim: true },
    minimumRentalDays: { type: Number, required: true, min: 1, default: 1 },
    images: { type: [String], required: true, default: [] },
    rating: { type: Number, required: true, min: 0, max: 5, default: 0 },
    featured: { type: Boolean, required: true, default: false },
    owner: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true },
);

const paymentSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: "User", required: true },
    item: { type: Schema.Types.ObjectId, ref: "RentalItem", required: true },
    rentalRequest: { type: Schema.Types.ObjectId, ref: "RentalRequest" },
    rentalDays: { type: Number, required: true, min: 1 },
    dailyPrice: { type: Number, required: true, min: 1 },
    securityDeposit: { type: Number, required: true, min: 0 },
    rentalAmount: { type: Number, required: true, min: 1 },
    totalAmount: { type: Number, required: true, min: 1 },
    currency: { type: String, required: true, default: "bdt" },
    stripeSessionId: { type: String, required: true, unique: true },
    paymentStatus: { type: String, enum: ["pending", "paid", "failed", "cancelled"], required: true, default: "pending" },
  },
  { timestamps: true },
);

const rentalRequestSchema = new Schema(
  {
    item: { type: Schema.Types.ObjectId, ref: "RentalItem", required: true },
    renter: { type: Schema.Types.ObjectId, ref: "User", required: true },
    owner: { type: Schema.Types.ObjectId, ref: "User", required: true },
    rentalDays: { type: Number, required: true, min: 1 },
    dailyPrice: { type: Number, required: true, min: 1 },
    securityDeposit: { type: Number, required: true, min: 0 },
    rentalAmount: { type: Number, required: true, min: 1 },
    totalAmount: { type: Number, required: true, min: 1 },
    status: { type: String, enum: ["pending", "accepted", "rejected", "cancelled", "paid"], required: true, default: "pending" },
    renterMessage: { type: String, trim: true },
    ownerNote: { type: String, trim: true },
    payment: { type: Schema.Types.ObjectId, ref: "Payment" },
  },
  { timestamps: true },
);

const contactMessageSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    subject: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true },
  },
  { timestamps: true },
);

const User = mongoose.models.User || mongoose.model("User", userSchema);
const RentalItemModel = mongoose.models.RentalItem || mongoose.model("RentalItem", rentalItemSchema);
const Payment = mongoose.models.Payment || mongoose.model("Payment", paymentSchema);
const RentalRequest = mongoose.models.RentalRequest || mongoose.model("RentalRequest", rentalRequestSchema);
const ContactMessage = mongoose.models.ContactMessage || mongoose.model("ContactMessage", contactMessageSchema);

const registerSchema = z
  .object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().optional(),
    location: z.string().optional(),
    avatar: z.string().url().optional().or(z.literal("")),
    password: z.string().min(6),
    confirmPassword: z.string().min(6),
  })
  .refine((data) => data.password === data.confirmPassword, { message: "Passwords do not match", path: ["confirmPassword"] });

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

const profileUpdateSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  phone: z.string().optional(),
  location: z.string().optional(),
  avatar: z.string().url().optional().or(z.literal("")),
});

const itemCreateSchema = z.object({
  title: z.string().min(3),
  shortDescription: z.string().min(10),
  fullDescription: z.string().min(20),
  category: z.enum(itemCategories as [ItemCategory, ...ItemCategory[]]),
  dailyPrice: z.coerce.number().positive(),
  securityDeposit: z.coerce.number().min(0),
  location: z.string().min(2),
  condition: z.enum(conditions),
  availability: z.enum(availabilities).default("available"),
  brand: z.string().optional(),
  model: z.string().optional(),
  minimumRentalDays: z.coerce.number().int().positive().default(1),
  images: z.array(z.string().url()).min(1).max(3),
});

const itemUpdateSchema = itemCreateSchema.partial().refine((data) => Object.keys(data).length > 0, {
  message: "At least one item field is required",
});

const contactSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  subject: z.string().min(3),
  message: z.string().min(10),
});

const checkoutSchema = z.object({
  itemId: z.string().min(1).optional(),
  requestId: z.string().min(1).optional(),
  rentalDays: z.coerce.number().int().positive().optional(),
});

const rentalRequestCreateSchema = z.object({
  itemId: z.string().min(1),
  rentalDays: z.coerce.number().int().positive(),
  renterMessage: z.string().max(500).optional(),
});

const rentalRequestStatusSchema = z.object({
  status: z.enum(["accepted", "rejected"]),
  ownerNote: z.string().max(500).optional(),
});

const adminRoleUpdateSchema = z.object({
  role: z.enum(userRoles),
});

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
}

function createSlug(title: string) {
  const suffix = Math.random().toString(36).slice(2, 8);
  return `${title.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}-${suffix}`;
}

function signToken(payload: JwtPayload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is not configured");
  return jwt.sign(payload, secret, { expiresIn: jwtExpiresIn as jwt.SignOptions["expiresIn"] });
}

function roleForEmail(email: string, fallback: UserRole = "user"): UserRole {
  return adminEmails.includes(email.toLowerCase()) ? "admin" : fallback;
}

function setAuthCookie(res: Response, token: string) {
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: cookieMaxAgeDays * 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookie(res: Response) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
  });
}

function toSafeUser(user: any) {
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    location: user.location,
    authProvider: user.authProvider,
    role: user.role,
    avatar: user.avatar,
    createdAt: user.createdAt,
  };
}

function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const bearerToken = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice("Bearer ".length)
    : "";
  const token = req.cookies?.[cookieName] || bearerToken;
  if (!token) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET is not configured");
    req.user = jwt.verify(token, secret) as JwtPayload;
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

function adminMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  User.findById(req.user?.userId)
    .then(async (user) => {
      if (!user) {
        res.status(403).json({ message: "Admin access required" });
        return;
      }

      const preferredRole = roleForEmail(user.email, user.role);
      if (preferredRole === "admin" && user.role !== "admin") {
        user.role = "admin";
        await user.save();
      }

      if (user.role !== "admin") {
        res.status(403).json({ message: "Admin access required" });
        return;
      }

      if (req.user) req.user.role = "admin";
      next();
    })
    .catch(next);
}

async function connectMongo(required = false) {
  if (!process.env.MONGO_URI) {
    const message = "MONGO_URI is not configured; database routes need it.";
    if (required) throw new Error(message);
    console.warn(message);
    return;
  }

  if (mongoose.connection.readyState === 1) return;
  if (!mongoConnectionPromise || mongoose.connection.readyState === 0 || mongoose.connection.readyState === 3) {
    mongoConnectionPromise = mongoose.connect(process.env.MONGO_URI);
  }

  try {
    await mongoConnectionPromise;
    console.log("MongoDB connected");
  } catch (error) {
    mongoConnectionPromise = null;
    if (required) throw error;
    throw error;
  }
}

app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  }),
);
app.use(
  cors({
    origin: clientUrl,
    credentials: true,
  }),
);
app.use(
  rateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    max: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);
app.use(cookieParser());
app.use(
  "/api",
  asyncHandler(async (req, res, next) => {
    if (req.path === "/health") {
      next();
      return;
    }

    try {
      await connectMongo(true);
      next();
    } catch {
      res.status(503).json({ message: "Database connection is unavailable. Please try again shortly." });
    }
  }),
);
app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  asyncHandler(async (req, res) => {
    if (!stripe) {
      res.json({ received: true, skipped: "Stripe is not configured" });
      return;
    }

    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      res.json({ received: true, skipped: "Stripe webhook secret is not configured yet" });
      return;
    }

    const signature = req.headers["stripe-signature"];
    if (!signature) {
      res.status(400).json({ message: "Missing Stripe signature" });
      return;
    }

    const event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
    if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
      const session = event.data.object as Stripe.Checkout.Session;
      const payment = await Payment.findOneAndUpdate(
        { stripeSessionId: session.id },
        { paymentStatus: "paid" },
        { new: true },
      );
      if (payment) {
        await RentalItemModel.findByIdAndUpdate(payment.item, { availability: "rented" });
        if (payment.rentalRequest) {
          await RentalRequest.findByIdAndUpdate(payment.rentalRequest, { status: "paid", payment: payment._id });
        }
      }
    }

    if (event.type === "checkout.session.expired" || event.type === "checkout.session.async_payment_failed") {
      const session = event.data.object as Stripe.Checkout.Session;
      await Payment.findOneAndUpdate({ stripeSessionId: session.id }, { paymentStatus: "failed" });
    }

    res.json({ received: true });
  }),
);
app.use(express.json());

app.get("/", (_req: Request, res: Response) => {
  res.json({
    message: "ShareBari server is running",
    status: "ok",
  });
});

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const data = registerSchema.parse(req.body);
    const existingUser = await User.findOne({ email: data.email.toLowerCase() });
    if (existingUser) {
      res.status(409).json({ message: "Email is already registered" });
      return;
    }

    const hashedPassword = await bcrypt.hash(data.password, bcryptSaltRounds);
    const role = roleForEmail(data.email);
    const user = await User.create({
      name: data.name,
      email: data.email.toLowerCase(),
      phone: data.phone,
      location: data.location,
      avatar: data.avatar || undefined,
      password: hashedPassword,
      authProvider: "local",
      role,
    });
    const token = signToken({ userId: String(user._id), email: user.email, role: user.role });
    setAuthCookie(res, token);
    res.status(201).json({ data: toSafeUser(user), token });
  }),
);

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const data = loginSchema.parse(req.body);
    const user = await User.findOne({ email: data.email.toLowerCase() }).select("+password");
    if (!user || !user.password) {
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    const isPasswordValid = await bcrypt.compare(data.password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    const preferredRole = roleForEmail(user.email, user.role);
    if (preferredRole !== user.role) {
      user.role = preferredRole;
      await user.save();
    }
    const token = signToken({ userId: String(user._id), email: user.email, role: user.role });
    setAuthCookie(res, token);
    res.json({ data: toSafeUser(user), token });
  }),
);

app.post(
  "/api/auth/google",
  asyncHandler(async (req, res) => {
    const credential = z.object({ credential: z.string().min(1) }).parse(req.body).credential;
    if (!googleClient || !process.env.GOOGLE_CLIENT_ID) {
      res.status(503).json({ message: "Google login is not configured" });
      return;
    }

    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.email) {
      res.status(401).json({ message: "Invalid Google credential" });
      return;
    }

    const role = roleForEmail(payload.email);
    const user = await User.findOneAndUpdate(
      { email: payload.email.toLowerCase() },
      {
        ...(role === "admin" ? { role } : {}),
        $setOnInsert: {
          name: payload.name || payload.email,
          email: payload.email.toLowerCase(),
          googleId: payload.sub,
          avatar: payload.picture,
          authProvider: "google",
          role,
        },
      },
      { new: true, upsert: true },
    );
    const token = signToken({ userId: String(user._id), email: user.email, role: user.role });
    setAuthCookie(res, token);
    res.json({ data: toSafeUser(user), token });
  }),
);

app.post("/api/auth/logout", (_req: Request, res: Response) => {
  clearAuthCookie(res);
  res.json({ message: "Logged out" });
});

app.get(
  "/api/auth/me",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const user = await User.findById(req.user?.userId);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ data: toSafeUser(user) });
  }),
);

app.patch(
  "/api/auth/me",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const data = profileUpdateSchema.parse(req.body);
    const email = data.email.toLowerCase();
    const existingUser = await User.findOne({ email, _id: { $ne: req.user?.userId } });
    if (existingUser) {
      res.status(409).json({ message: "Email is already used by another account" });
      return;
    }

    const user = await User.findByIdAndUpdate(
      req.user?.userId,
      {
        name: data.name,
        email,
        phone: data.phone,
        location: data.location,
        avatar: data.avatar || undefined,
      },
      { new: true },
    );
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ data: toSafeUser(user) });
  }),
);

app.get(
  "/api/items",
  asyncHandler(async (req, res) => {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = 12;
    const skip = (page - 1) * limit;
    const sort = String(req.query.sort ?? "newest");
    const filter: Record<string, unknown> = {};
    const search = String(req.query.search ?? "").trim();

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: "i" } },
        { shortDescription: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }
    if (req.query.category) filter.category = req.query.category;
    if (req.query.location) filter.location = { $regex: String(req.query.location), $options: "i" };
    if (req.query.condition) filter.condition = req.query.condition;
    if (req.query.availability) filter.availability = req.query.availability;
    if (req.query.minPrice || req.query.maxPrice) {
      filter.dailyPrice = {
        ...(req.query.minPrice ? { $gte: Number(req.query.minPrice) } : {}),
        ...(req.query.maxPrice ? { $lte: Number(req.query.maxPrice) } : {}),
      };
    }

    const sortMap: Record<string, Record<string, 1 | -1>> = {
      oldest: { createdAt: 1 },
      "price-asc": { dailyPrice: 1 },
      "price-desc": { dailyPrice: -1 },
      rating: { rating: -1 },
      newest: { createdAt: -1 },
    };
    const [items, total] = await Promise.all([
      RentalItemModel.find(filter).populate("owner", "name email phone location").sort(sortMap[sort] || sortMap.newest).skip(skip).limit(limit),
      RentalItemModel.countDocuments(filter),
    ]);

    res.json({ data: items, pagination: { page, limit, total, totalPages: Math.max(Math.ceil(total / limit), 1) } });
  }),
);

app.post(
  "/api/items",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const data = itemCreateSchema.parse(req.body);
    const item = await RentalItemModel.create({
      ...data,
      slug: createSlug(data.title),
      owner: req.user?.userId,
      rating: 0,
      featured: false,
    });

    res.status(201).json({ data: item });
  }),
);

app.get(
  "/api/items/my-items",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const items = await RentalItemModel.find({ owner: req.user?.userId }).sort({ createdAt: -1 });
    res.json({ data: items });
  }),
);

app.get(
  "/api/items/featured",
  asyncHandler(async (_req, res) => {
    const items = await RentalItemModel.find({ featured: true, availability: "available" }).sort({ rating: -1 }).limit(8);
    res.json({ data: items });
  }),
);

app.get(
  "/api/items/recent",
  asyncHandler(async (_req, res) => {
    const items = await RentalItemModel.find().sort({ createdAt: -1 }).limit(8);
    res.json({ data: items });
  }),
);

app.get(
  "/api/items/:id",
  asyncHandler(async (req, res) => {
    const item = mongoose.isValidObjectId(req.params.id)
      ? await RentalItemModel.findById(req.params.id).populate("owner", "name email phone location")
      : await RentalItemModel.findOne({ slug: req.params.id }).populate("owner", "name email phone location");
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }

    res.json({ data: item });
  }),
);

app.patch(
  "/api/items/:id",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      res.status(400).json({ message: "Invalid item ID" });
      return;
    }

    const data = itemUpdateSchema.parse(req.body);
    const item = await RentalItemModel.findById(req.params.id);
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    if (String(item.owner) !== req.user?.userId) {
      res.status(403).json({ message: "You can update only your own listings" });
      return;
    }

    const titleChanged = Boolean(data.title && data.title !== item.title);
    Object.assign(item, data);
    if (titleChanged && data.title) {
      item.slug = createSlug(data.title);
    }

    await item.save();
    await item.populate("owner", "name email phone location");
    res.json({ data: item });
  }),
);

app.delete(
  "/api/items/:id",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      res.status(400).json({ message: "Invalid item ID" });
      return;
    }
    const item = await RentalItemModel.findById(req.params.id);
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    if (String(item.owner) !== req.user?.userId) {
      res.status(403).json({ message: "You can delete only your own listings" });
      return;
    }

    await item.deleteOne();
    res.json({ message: "Item deleted" });
  }),
);

app.get(
  "/api/dashboard/stats",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const owner = new mongoose.Types.ObjectId(req.user?.userId);
    const [totalListedItems, availableItems, rentedItems, priceAgg, byCategory, byAvailability] = await Promise.all([
      RentalItemModel.countDocuments({ owner }),
      RentalItemModel.countDocuments({ owner, availability: "available" }),
      RentalItemModel.countDocuments({ owner, availability: "rented" }),
      RentalItemModel.aggregate([{ $match: { owner } }, { $group: { _id: null, averageDailyPrice: { $avg: "$dailyPrice" } } }]),
      RentalItemModel.aggregate([{ $match: { owner } }, { $group: { _id: "$category", count: { $sum: 1 } } }]),
      RentalItemModel.aggregate([{ $match: { owner } }, { $group: { _id: "$availability", count: { $sum: 1 } } }]),
    ]);

    res.json({
      data: {
        totalListedItems,
        availableItems,
        rentedItems,
        averageDailyPrice: Math.round(priceAgg[0]?.averageDailyPrice || 0),
        byCategory,
        byAvailability,
      },
    });
  }),
);

app.post(
  "/api/rental-requests",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const data = rentalRequestCreateSchema.parse(req.body);
    const item = await RentalItemModel.findById(data.itemId);
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    if (item.availability !== "available") {
      res.status(400).json({ message: "This item is not available for new rental requests" });
      return;
    }
    if (String(item.owner) === req.user?.userId) {
      res.status(400).json({ message: "You cannot request your own listing" });
      return;
    }

    const rentalDays = Math.max(data.rentalDays, item.minimumRentalDays);
    const rentalAmount = item.dailyPrice * rentalDays;
    const totalAmount = rentalAmount + item.securityDeposit;
    const rentalRequest = await RentalRequest.create({
      item: item._id,
      renter: req.user?.userId,
      owner: item.owner,
      rentalDays,
      dailyPrice: item.dailyPrice,
      securityDeposit: item.securityDeposit,
      rentalAmount,
      totalAmount,
      renterMessage: data.renterMessage,
      status: "pending",
    });

    res.status(201).json({ data: rentalRequest });
  }),
);

app.get(
  "/api/rental-requests/my",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const requests = await RentalRequest.find({ renter: req.user?.userId })
      .populate("item", "title slug images location category availability")
      .populate("owner", "name email phone location")
      .sort({ createdAt: -1 });
    res.json({ data: requests });
  }),
);

app.get(
  "/api/rental-requests/owner",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const requests = await RentalRequest.find({ owner: req.user?.userId })
      .populate("item", "title slug images location category availability")
      .populate("renter", "name email phone location avatar")
      .sort({ createdAt: -1 });
    res.json({ data: requests });
  }),
);

app.patch(
  "/api/rental-requests/:id/status",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      res.status(400).json({ message: "Invalid request ID" });
      return;
    }

    const data = rentalRequestStatusSchema.parse(req.body);
    const rentalRequest = await RentalRequest.findById(req.params.id);
    if (!rentalRequest) {
      res.status(404).json({ message: "Rental request not found" });
      return;
    }
    if (String(rentalRequest.owner) !== req.user?.userId) {
      res.status(403).json({ message: "Only the owner can update this request" });
      return;
    }
    if (rentalRequest.status !== "pending") {
      res.status(400).json({ message: "Only pending requests can be updated" });
      return;
    }

    rentalRequest.status = data.status;
    rentalRequest.ownerNote = data.ownerNote;
    await rentalRequest.save();

    if (data.status === "accepted") {
      await RentalItemModel.findByIdAndUpdate(rentalRequest.item, { availability: "unavailable" });
    }

    res.json({ data: rentalRequest });
  }),
);

app.get(
  "/api/admin/users",
  authMiddleware,
  adminMiddleware,
  asyncHandler(async (_req: AuthRequest, res) => {
    const [users, listingCounts, totalItems, totalPayments] = await Promise.all([
      User.find().sort({ createdAt: -1 }),
      RentalItemModel.aggregate([{ $group: { _id: "$owner", listedItems: { $sum: 1 } } }]),
      RentalItemModel.countDocuments(),
      Payment.countDocuments(),
    ]);
    const listingCountMap = new Map(listingCounts.map((item) => [String(item._id), item.listedItems]));
    const safeUsers = users.map((user) => ({
      ...toSafeUser(user),
      listedItems: listingCountMap.get(String(user._id)) || 0,
    }));

    res.json({
      data: safeUsers,
      summary: {
        totalUsers: users.length,
        adminUsers: users.filter((user) => user.role === "admin").length,
        regularUsers: users.filter((user) => user.role !== "admin").length,
        totalItems,
        totalPayments,
      },
    });
  }),
);

app.patch(
  "/api/admin/users/:id/role",
  authMiddleware,
  adminMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      res.status(400).json({ message: "Invalid user ID" });
      return;
    }

    const data = adminRoleUpdateSchema.parse(req.body);
    if (req.params.id === req.user?.userId && data.role !== "admin") {
      res.status(400).json({ message: "You cannot remove your own admin access" });
      return;
    }

    const user = await User.findByIdAndUpdate(req.params.id, { role: data.role }, { new: true });
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ data: toSafeUser(user) });
  }),
);

app.post(
  "/api/contact",
  asyncHandler(async (req, res) => {
    const data = contactSchema.parse(req.body);
    await ContactMessage.create(data);
    res.status(201).json({ message: "Contact message received" });
  }),
);

app.post(
  "/api/payments/create-checkout-session",
  authMiddleware,
  asyncHandler(async (req: AuthRequest, res) => {
    const data = checkoutSchema.parse(req.body);
    let requestForPayment: any = null;
    let item: any = null;
    let rentalDays = data.rentalDays || 1;

    if (data.requestId) {
      requestForPayment = await RentalRequest.findById(data.requestId).populate("item");
      if (!requestForPayment) {
        res.status(404).json({ message: "Rental request not found" });
        return;
      }
      if (String(requestForPayment.renter) !== req.user?.userId) {
        res.status(403).json({ message: "You can pay only for your own request" });
        return;
      }
      if (requestForPayment.status !== "accepted") {
        res.status(400).json({ message: "Owner must accept this request before payment" });
        return;
      }
      item = requestForPayment.item;
      rentalDays = requestForPayment.rentalDays;
    } else if (data.itemId) {
      res.status(400).json({ message: "Send a rental request and wait for owner approval before payment" });
      return;
    }

    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    if (!stripe) {
      res.status(503).json({ message: "Stripe is not configured" });
      return;
    }

    const rentalAmount = requestForPayment?.rentalAmount ?? item.dailyPrice * rentalDays;
    const totalAmount = requestForPayment?.totalAmount ?? rentalAmount + item.securityDeposit;
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: stripeCurrency,
            product_data: { name: item.title, description: item.shortDescription },
            unit_amount: Math.round(totalAmount * 100),
          },
          quantity: 1,
        },
      ],
      success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${clientUrl}/payment/cancel`,
      metadata: { itemId: String(item._id), userId: String(req.user?.userId), rentalDays: String(rentalDays), requestId: data.requestId || "" },
    });

    const payment = await Payment.create({
      user: req.user?.userId,
      item: item._id,
      rentalRequest: requestForPayment?._id,
      rentalDays,
      dailyPrice: item.dailyPrice,
      securityDeposit: item.securityDeposit,
      rentalAmount,
      totalAmount,
      currency: stripeCurrency,
      stripeSessionId: session.id,
      paymentStatus: "pending",
    });

    if (requestForPayment) {
      requestForPayment.payment = payment._id;
      await requestForPayment.save();
    }

    res.status(201).json({ data: { sessionId: session.id, checkoutUrl: session.url } });
  }),
);

app.get(
  "/api/payments/session/:sessionId",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const payment = await Payment.findOne({ stripeSessionId: req.params.sessionId });
    if (!payment) {
      res.status(404).json({ message: "Payment session not found" });
      return;
    }

    res.json({ data: payment });
  }),
);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ message: "Route not found" });
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof z.ZodError) {
    res.status(400).json({ message: "Validation failed", issues: error.issues });
    return;
  }

  const message = error instanceof Error ? error.message : "Internal server error";
  res.status(500).json({ message: isProduction ? "Internal server error" : message });
});

connectMongo().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "MongoDB connection failed";
  console.error(message);
});

async function ensureDemoAccount() {
  try {
    const existingDemo = await User.findOne({ email: "demo@sharebari.com" });
    if (!existingDemo) {
      const hashedPassword = await bcrypt.hash("DemoPassword123", bcryptSaltRounds);
      await User.create({
        name: "Demo User",
        email: "demo@sharebari.com",
        phone: "+880 1700 000000",
        location: "Dhaka, Bangladesh",
        password: hashedPassword,
        authProvider: "local",
        role: "user",
        avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=demo",
      });
      console.log("✓ Demo account created");
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("duplicate")) {
      // Demo account already exists
    } else {
      console.error("Error creating demo account:", error);
    }
  }
}

if (process.env.VERCEL !== "1") {
  app.listen(port, async () => {
    await ensureDemoAccount();
    console.log(`ShareBari server listening on port ${port}`);
  });
}

export default app;
