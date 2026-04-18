# Project: [Your Project Name]
> Mercy University AI Hackathon — April 18–19, 2026

## What This Project Does
[One or two sentences describing what your AI agent/chatbot does and what problem it solves.]

## Challenge Domain
[ ] Health
[ ] Accessibility
[ ] Finance
[ ] Sustainability
[ ] Public Safety

## Team
- [Name] — AI / Agent logic
- [Name] — Frontend / UI
- [Name] — Data / API integrations

---

## Tech Stack
- **Frontend**: [e.g. plain HTML/CSS/JS or React]
- **Backend**: [e.g. Node.js / Python Flask]
- **AI**: Anthropic Claude API (`claude-sonnet-4-20250514`)
- **Auth/Keys**: Stored in `.env` — never commit this file

## Project Structure
```
/
├── CLAUDE.md          ← You are here
├── .env               ← API keys (never commit)
├── .gitignore
├── index.html         ← Main UI
├── server.js          ← Backend / API handler
└── README.md
```

---

## Claude API Usage
- Model: `claude-sonnet-4-20250514`
- Max tokens: 1024 (adjust as needed)
- API key is read from `process.env.ANTHROPIC_API_KEY`

## Coding Conventions
- Keep responses concise and user-friendly
- Handle API errors gracefully — always show a fallback message
- Comment non-obvious logic
- No secrets hardcoded in source files

## What NOT to Do
- Do not commit `.env`
- Do not use `sudo npm install -g`
- Do not push directly to `main` — use your own branch and PR

---

## Current Focus / In Progress
[Update this section as the day goes on so teammates and Claude stay in sync]

- [ ] Scaffold project structure
- [ ] Connect Claude API
- [ ] Build core UI
- [ ] Demo-ready by 4:00 PM
