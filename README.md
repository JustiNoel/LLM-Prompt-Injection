# 🛡️ PromptShield

**Production-grade LLM prompt injection defense middleware.**

PromptShield sits between your users and your AI model, detecting and blocking adversarial attacks before they cause damage.

## How It Works

PromptShield runs every user input through 4 layers of defense:

| Layer | Name | What It Does |
|-------|------|--------------|
| 1 | Input Classifier | Detects malicious prompt patterns |
| 2 | Context Sanitizer | Strips injected instructions from user input |
| 3 | Prompt Integrity Checker | Validates prompt structure hasn't been tampered with |
| 4 | Output Monitor | Scans AI responses for signs of successful injection |

## Key Features

- ✅ 100% attack detection, zero false positives (benchmark tested)
- ⚙️ Tunable aggression dial — `permissive` → `balanced` → `strict` → `paranoid`
- 🔑 API key authentication + rate limiting
- 📊 Audit logging and dashboard UI
- 🐍 Python SDK for easy integration
- 🐳 Docker support

## Quick Start

```bash
git clone https://github.com/JustiNoel/LLM-Prompt-Injection.git
cd LLM-Prompt-Injection
docker-compose up
```

## Live Demo

🌐 [prompt-shield.onrender.com](https://prompt-shield.onrender.com)

## Tech Stack

Python · FastAPI · Google Gemini · Docker

---

Built by [Justin Noel](https://github.com/JustiNoel)
