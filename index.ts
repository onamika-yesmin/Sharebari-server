import cors from "cors";
import dotenv from "dotenv";
import express, { type Request, type Response } from "express";

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 5000;

app.use(cors());
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

app.listen(port, () => {
  console.log(`ShareBari server listening on port ${port}`);
});

export default app;
