import express from "express";
import cors from "cors";
import axios from "axios";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

app.post("/api/parse", async (req, res) => {
  const { method, content } = req.body;

  try {
    if (method === "text") {
      const response = await axios.post("http://localhost:8000/nlp/parse", {
        text: content,
      });
      res.json(response.data);
    } else {
      res.status(400).json({ error: "Unsupported method" });
    }
  } catch (error: any) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Node server running at http://localhost:${PORT}`);
});



