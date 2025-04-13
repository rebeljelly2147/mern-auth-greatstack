import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";

import connectDB from "./config/mongodb.js";

import authRouter from "./routes/authRoutes.js";


const app = express();

const port = process.env.PORT || 5000;
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

// These are API endpoints
app.get("/", (req, res) => {
    res.send("API working Fine!");
});
app.use("/api/auth", authRouter);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
 