import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import cors from "cors";
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
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;

type ItemCategory =
  | "tools-equipment"
  | "cameras-electronics"
  | "event-party"
  | "outdoor-sports"
  | "home-kitchen"
  | "books-learning";

type RentalItem = {
  id: string;
  title: string;
  shortDescription: string;
  fullDescription: string;
  category: ItemCategory;
  dailyPrice: number;
  securityDeposit: number;
  location: string;
  condition: "like-new" | "excellent" | "good" | "fair";
  availability: "available" | "rented" | "unavailable";
  images: string[];
  rating: number;
  featured: boolean;
  owner: {
    name: string;
    email: string;
    phone: string;
  };
  createdAt: string;
};

type JwtPayload = {
  userId: string;
  email: string;
  role: "user";
};

type AuthRequest = Request & {
  user?: JwtPayload;
};

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

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true },
    location: { type: String, trim: true },
    password: { type: String, select: false },
    googleId: { type: String },
    authProvider: { type: String, enum: ["local", "google"], required: true, default: "local" },
    role: { type: String, enum: ["user"], required: true, default: "user" },
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
const ContactMessage = mongoose.models.ContactMessage || mongoose.model("ContactMessage", contactMessageSchema);

const registerSchema = z
  .object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().optional(),
    location: z.string().optional(),
    password: z.string().min(6),
    confirmPassword: z.string().min(6),
  })
  .refine((data) => data.password === data.confirmPassword, { message: "Passwords do not match", path: ["confirmPassword"] });

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

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

const contactSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  subject: z.string().min(3),
  message: z.string().min(10),
});

const checkoutSchema = z.object({
  itemId: z.string().min(1),
  rentalDays: z.coerce.number().int().positive(),
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
  const token = req.cookies?.[cookieName];
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

async function connectMongo() {
  if (!process.env.MONGO_URI) {
    console.warn("MONGO_URI is not configured; database routes need it.");
    return;
  }
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connected");
  }
}

const rentalItems: RentalItem[] = [
  {
    id: "bosch-drill-kit",
    title: "Bosch Drill Kit",
    shortDescription: "Cordless drill with bit set for quick home repairs.",
    fullDescription: "A reliable drill kit for mounting shelves, assembling furniture, and handling weekend repair work.",
    category: "tools-equipment",
    dailyPrice: 450,
    securityDeposit: 1500,
    location: "Khulna",
    condition: "excellent",
    availability: "available",
    images: ["https://images.unsplash.com/photo-1504148455328-c376907d081c?auto=format&fit=crop&w=1200&q=80"],
    rating: 4.9,
    featured: true,
    owner: { name: "Nusrat Jahan", email: "nusrat@example.com", phone: "+8801711000001" },
    createdAt: "2026-07-01T10:00:00.000Z",
  },
  {
    id: "canon-eos-camera",
    title: "Canon EOS Camera",
    shortDescription: "Beginner-friendly DSLR body with portrait lens.",
    fullDescription: "Capture events, product shots, and family portraits with a clean DSLR setup.",
    category: "cameras-electronics",
    dailyPrice: 1200,
    securityDeposit: 6000,
    location: "Dhaka",
    condition: "like-new",
    availability: "available",
    images: ["https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&w=1200&q=80"],
    rating: 4.8,
    featured: true,
    owner: { name: "Rafi Ahmed", email: "rafi@example.com", phone: "+8801711000002" },
    createdAt: "2026-07-02T10:00:00.000Z",
  },
  {
    id: "party-speaker-set",
    title: "Party Speaker Set",
    shortDescription: "Bluetooth speaker pair for birthdays and small events.",
    fullDescription: "Two powered speakers with microphone support for small gatherings.",
    category: "event-party",
    dailyPrice: 900,
    securityDeposit: 3000,
    location: "Chattogram",
    condition: "good",
    availability: "available",
    images: ["https://images.unsplash.com/photo-1545454675-3531b543be5d?auto=format&fit=crop&w=1200&q=80"],
    rating: 4.6,
    featured: true,
    owner: { name: "Mahin Chowdhury", email: "mahin@example.com", phone: "+8801711000003" },
    createdAt: "2026-07-03T10:00:00.000Z",
  },
  {
    id: "camping-tent-four-person",
    title: "Four Person Camping Tent",
    shortDescription: "Water-resistant tent for weekend outdoor trips.",
    fullDescription: "Compact tent with rain cover, pegs, and carry bag.",
    category: "outdoor-sports",
    dailyPrice: 650,
    securityDeposit: 2500,
    location: "Sylhet",
    condition: "excellent",
    availability: "available",
    images: ["https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?auto=format&fit=crop&w=1200&q=80"],
    rating: 4.7,
    featured: false,
    owner: { name: "Sadia Karim", email: "sadia@example.com", phone: "+8801711000004" },
    createdAt: "2026-07-04T10:00:00.000Z",
  },
];

app.use(helmet());
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
    const user = await User.create({
      name: data.name,
      email: data.email.toLowerCase(),
      phone: data.phone,
      location: data.location,
      password: hashedPassword,
      authProvider: "local",
      role: "user",
    });
    const token = signToken({ userId: String(user._id), email: user.email, role: "user" });
    setAuthCookie(res, token);
    res.status(201).json({ data: toSafeUser(user) });
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

    const token = signToken({ userId: String(user._id), email: user.email, role: "user" });
    setAuthCookie(res, token);
    res.json({ data: toSafeUser(user) });
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

    const user = await User.findOneAndUpdate(
      { email: payload.email.toLowerCase() },
      {
        $setOnInsert: {
          name: payload.name || payload.email,
          email: payload.email.toLowerCase(),
          googleId: payload.sub,
          avatar: payload.picture,
          authProvider: "google",
          role: "user",
        },
      },
      { new: true, upsert: true },
    );
    const token = signToken({ userId: String(user._id), email: user.email, role: "user" });
    setAuthCookie(res, token);
    res.json({ data: toSafeUser(user) });
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
    const item = await RentalItemModel.findById(data.itemId);
    if (!item) {
      res.status(404).json({ message: "Item not found" });
      return;
    }
    if (!stripe) {
      res.status(503).json({ message: "Stripe is not configured" });
      return;
    }

    const rentalAmount = item.dailyPrice * data.rentalDays;
    const totalAmount = rentalAmount + item.securityDeposit;
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
      metadata: { itemId: String(item._id), userId: String(req.user?.userId), rentalDays: String(data.rentalDays) },
    });

    await Payment.create({
      user: req.user?.userId,
      item: item._id,
      rentalDays: data.rentalDays,
      dailyPrice: item.dailyPrice,
      securityDeposit: item.securityDeposit,
      rentalAmount,
      totalAmount,
      currency: stripeCurrency,
      stripeSessionId: session.id,
      paymentStatus: "pending",
    });

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

app.get("/api/items", (req: Request, res: Response) => {
  const search = String(req.query.search ?? "").toLowerCase();
  const category = String(req.query.category ?? "");
  const location = String(req.query.location ?? "").toLowerCase();
  const condition = String(req.query.condition ?? "");
  const availability = String(req.query.availability ?? "");
  const sort = String(req.query.sort ?? "");

  const items = rentalItems
    .filter((item) => !search || [item.title, item.shortDescription, item.location].join(" ").toLowerCase().includes(search))
    .filter((item) => !category || item.category === category)
    .filter((item) => !location || item.location.toLowerCase().includes(location))
    .filter((item) => !condition || item.condition === condition)
    .filter((item) => !availability || item.availability === availability)
    .sort((a, b) => {
      if (sort === "price-asc") return a.dailyPrice - b.dailyPrice;
      if (sort === "price-desc") return b.dailyPrice - a.dailyPrice;
      if (sort === "rating") return b.rating - a.rating;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });

  res.json({
    data: items,
    pagination: {
      page: 1,
      limit: 12,
      total: items.length,
      totalPages: 1,
    },
  });
});

app.get("/api/items/featured", (_req: Request, res: Response) => {
  res.json({ data: rentalItems.filter((item) => item.featured) });
});

app.get("/api/items/recent", (_req: Request, res: Response) => {
  res.json({ data: [...rentalItems].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, 4) });
});

app.get("/api/items/:id", (req: Request, res: Response) => {
  const item = rentalItems.find((candidate) => candidate.id === req.params.id);
  if (!item) {
    res.status(404).json({ message: "Item not found" });
    return;
  }

  res.json({ data: item });
});

app.get("/api/dashboard/stats", (_req: Request, res: Response) => {
  const available = rentalItems.filter((item) => item.availability === "available").length;
  const rented = rentalItems.filter((item) => item.availability === "rented").length;
  const averageDailyPrice = Math.round(rentalItems.reduce((sum, item) => sum + item.dailyPrice, 0) / rentalItems.length);

  res.json({
    data: {
      totalListedItems: rentalItems.length,
      availableItems: available,
      rentedItems: rented,
      averageDailyPrice,
    },
  });
});

app.post("/api/contact", (req: Request, res: Response) => {
  const { name, email, subject, message } = req.body as Record<string, unknown>;
  if (!name || !email || !subject || !message) {
    res.status(400).json({ message: "Name, email, subject, and message are required" });
    return;
  }

  res.status(201).json({ message: "Contact message received" });
});

app.post("/api/payments/create-checkout-session", (req: Request, res: Response) => {
  const { itemId, rentalDays } = req.body as { itemId?: string; rentalDays?: number };
  const item = rentalItems.find((candidate) => candidate.id === itemId);

  if (!item || typeof rentalDays !== "number" || !Number.isInteger(rentalDays) || rentalDays < 1) {
    res.status(400).json({ message: "Valid itemId and rentalDays are required" });
    return;
  }

  const requestedRentalDays = rentalDays;
  const rentalAmount = item.dailyPrice * requestedRentalDays;
  const totalAmount = rentalAmount + item.securityDeposit;

  res.status(201).json({
    data: {
      id: `demo_checkout_${item.id}_${requestedRentalDays}`,
      itemId: item.id,
      rentalDays: requestedRentalDays,
      dailyPrice: item.dailyPrice,
      securityDeposit: item.securityDeposit,
      rentalAmount,
      totalAmount,
      currency: "bdt",
      checkoutUrl: `${clientUrl}/payment/success`,
    },
  });
});

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

if (process.env.VERCEL !== "1") {
  app.listen(port, () => {
    console.log(`ShareBari server listening on port ${port}`);
  });
}

export default app;
