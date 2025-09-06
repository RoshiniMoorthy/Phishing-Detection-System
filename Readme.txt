# 🔐 Phishing Detector

A lightweight **client-side phishing URL detection system** built with **HTML, TailwindCSS, and JavaScript**.  
It analyzes URLs using heuristic scoring and flags them as **Low, Medium, or High Risk**.  
The project is **privacy-friendly** and can be deployed for free on **Netlify**.

---

## 🚀 Features
- ✅ Heuristic scoring (Low / Medium / High risk)
- ✅ Feature extraction (hostname, path, suspicious keywords, etc.)
- ✅ Detects common phishing patterns:
  - IP-based hostnames
  - Suspicious TLDs (`.ru`, `.cn`, `.tk`, etc.)
  - URL shorteners (`bit.ly`, `tinyurl`)
  - Brand keywords (PayPal, Google, Microsoft, etc.)
- ✅ Modern UI with **TailwindCSS**
- ✅ 100% client-side (no backend, no data leaks)

---

## 📂 Project Structure
phishing-detector/
│
├── index.html # Main webpage
├── style.css # Custom styles
├── script.js # Detection logic (feature extraction + scoring)
├── netlify.toml # Netlify config (for deployment)
└── README.md # Project documentation


⚠️ Disclaimer
This tool uses simple heuristics and cannot guarantee 100% accuracy.
It should be used only as a guide — not as a replacement for professional security solutions.
Always avoid entering sensitive information on suspicious websites.

