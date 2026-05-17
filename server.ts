import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import axios from "axios";
import ipaddr from "ipaddr.js";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // In-memory scan state
  const scans: Record<string, any> = {};

  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/api/files", (req, res) => {
    // Mock detecting files in environment
    res.json([
      { name: "targets.txt", path: "/tmp/targets.txt" },
      { name: "vps_list.txt", path: "/tmp/vps_list.txt" },
    ]);
  });

  app.post("/api/scan/start", async (req, res) => {
    const { mode, target, ports } = req.body;
    const scanId = Math.random().toString(36).substring(7);
    
    let ips: string[] = [];
    
    if (mode === "CIDR") {
      try {
        const network = ipaddr.parseCIDR(target);
        // Simplistic IP generation for demo (limited to /24 for safety in web UI)
        if (network[1] < 24) {
          return res.status(400).json({ error: "CIDR too large for web demo (max /24)" });
        }
        
        // This is a bit complex with ipaddr.js to iterate, so we'll do a simple loop for /24
        const [baseAddr, mask] = network;
        const range = Math.pow(2, 32 - mask);
        const base = baseAddr.toByteArray();
        for (let i = 0; i < Math.min(range, 256); i++) {
          const current = [...base];
          current[3] += i;
          ips.push(current.join("."));
        }
      } catch (e) {
        return res.status(400).json({ error: "Invalid CIDR" });
      }
    } else {
      // Mock File - for demo we just use the target string if it's already a list or single URL
      ips = target.split(",").map((s: string) => s.trim());
    }

    scans[scanId] = {
      progress: 0,
      total: ips.length * (ports?.length || 1),
      current: 0,
      hits: [],
      status: "running",
      ips,
      ports: ports || [80, 443]
    };

    res.json({ scanId });

    // Background scan (simplified)
    const scan = scans[scanId];
    (async () => {
      for (const ip of scan.ips) {
        for (const port of scan.ports) {
          if (scan.status !== "running") break;
          
          scan.current++;
          scan.progress = Math.round((scan.current / scan.total) * 100);
          
          try {
            const protocol = port === 443 ? "https" : "http";
            const url = `${protocol}://${ip}:${port}`;
            
            const startTime = Date.now();
            const response = await axios.get(url, { 
              timeout: 2000, 
              validateStatus: () => true,
              maxRedirects: 0
            });
            
            scan.hits.push({
              target: `${ip}:${port}`,
              server: response.headers["server"] || "Unknown",
              status: `${response.status} ${response.statusText}`,
              method: "GET",
              version: "HTTP/1.1",
              time: Date.now() - startTime
            });
          } catch (e) {
            // Ignore errors
          }
          
          // Small delay to simulate and not overwhelm
          await new Promise(r => setTimeout(r, 100));
        }
        if (scan.status !== "running") break;
      }
      scan.status = "completed";
    })();
  });

  app.get("/api/scan/:id", (req, res) => {
    const scan = scans[req.params.id];
    if (!scan) return res.status(404).json({ error: "Not found" });
    res.json({
      progress: scan.progress,
      hits: scan.hits,
      status: scan.status,
      current: scan.current,
      total: scan.total
    });
  });

  app.post("/api/scan/:id/control", (req, res) => {
    const scan = scans[req.params.id];
    if (!scan) return res.status(404).json({ error: "Not found" });
    const { action } = req.body;
    if (action === "pause") scan.status = "paused";
    if (action === "resume") scan.status = "running";
    if (action === "stop") scan.status = "stopped";
    res.json({ status: scan.status });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
