# StoryLab — Project Context

## What it is
A community storytelling web app where people share stories of moving forward ("oyming") from dark points in their lives. Built for emotional support and connection.

## Stack
- **Backend:** Node.js + Express, NeDB (flat-file DB), bcryptjs, JWT, Resend (email)
- **Frontend:** Single-page app in one file — `public/index.html` (vanilla JS, no framework)
- **Fonts:** Newsreader (serif, story text) + Bricolage Grotesque (UI)
- **Theme:** Dark atmospheric — near-black bg (#080709), amber accent (#c8823e), rose accent (#9b3a52)

## File structure
```
server.js          — all API routes
public/index.html  — entire frontend (CSS + HTML + JS in one file)
data/              — NeDB flat files (users, stories, votes, comments, etc.)
```

## Deployment
- GitHub repo: https://github.com/davidksec/storylab
- Deployed on Railway — push to `master` branch triggers auto-deploy
- `git push` is all that's needed to deploy

## Key concepts
- **Oyming** — the site's core word, means "moving forward towards a better future"
- Stories have a **darkness** section and an optional **light** section (found hope / still searching)
- Users can post anonymously or logged in
- Moderation system: mod_level 0/1/2 + is_admin flag
- First-time visitors see a **welcome banner** (tracked via `localStorage` key `sl_seen`)

## Auth
- First registered user becomes admin automatically
- JWT stored in localStorage as `sl_token`

## Current state (as of March 2026)
- Welcome/landing banner added with "Oyming" definition, site explanation, and Read/Share CTAs
- Full CRUD for stories, comments, votes, reports, mod flags, password reset
