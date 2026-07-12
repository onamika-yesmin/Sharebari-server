import cors from "cors";
import dotenv from "dotenv";
import express, { type Request, type Response } from "express";

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 5000;
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

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

app.use(
  cors({
    origin: clientUrl,
    credentials: true,
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
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

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

if (process.env.VERCEL !== "1") {
  app.listen(port, () => {
    console.log(`ShareBari server listening on port ${port}`);
  });
}

export default app;
