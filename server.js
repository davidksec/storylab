const express   = require('express');
const Datastore = require('@seald-io/nedb');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');
const { Resend } = require('resend');

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const app    = express();
const SECRET = process.env.JWT_SECRET || 'sl-secret-change-in-production';

// Ensure data directory exists
fs.mkdirSync('data', { recursive: true });

// Datastores (each saves to its own flat file)
const db = {
  users:        new Datastore({ filename: 'data/users.db',        autoload: true }),
  stories:      new Datastore({ filename: 'data/stories.db',      autoload: true }),
  votes:        new Datastore({ filename: 'data/votes.db',        autoload: true }),
  comments:     new Datastore({ filename: 'data/comments.db',     autoload: true }),
  reports:      new Datastore({ filename: 'data/reports.db',      autoload: true }),
  reset_tokens: new Datastore({ filename: 'data/reset_tokens.db', autoload: true }),
};

db.users.ensureIndex({ fieldName: 'username', unique: true });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────
function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization?.slice(7), SECRET);
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}

function optAuth(req, res, next) {
  try {
    const t = req.headers.authorization?.slice(7);
    if (t) req.user = jwt.verify(t, SECRET);
  } catch {}
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Register ──────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username?.trim() || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const count    = await db.users.countAsync({});
  const is_admin = count === 0 ? 1 : 0;
  const hash     = bcrypt.hashSync(password, 10);

  try {
    const user = await db.users.insertAsync({
      username: username.trim(), password: hash, is_admin,
      email: email?.trim().toLowerCase() || '',
      joined: new Date().toISOString().slice(0, 10),
    });
    const payload = { id: user._id, username: user.username, is_admin: user.is_admin };
    res.json({ token: jwt.sign(payload, SECRET, { expiresIn: '30d' }), ...payload });
  } catch (e) {
    if (e.errorType === 'uniqueViolated')
      return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Login ─────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await db.users.findOneAsync({ username });
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid username or password' });
  const payload = { id: user._id, username: user.username, is_admin: user.is_admin };
  res.json({ token: jwt.sign(payload, SECRET, { expiresIn: '30d' }), ...payload });
});

// ── Helper: enrich stories with counts ───────────────────
async function enrich(storyList, userId) {
  if (!storyList.length) return [];
  const ids = storyList.map(s => s._id);
  const [allVotes, allComments] = await Promise.all([
    db.votes.findAsync({ story_id: { $in: ids } }),
    db.comments.findAsync({ story_id: { $in: ids } }),
  ]);
  return storyList.map(s => ({
    id:                s._id,
    title:             s.title,
    body:              s.body,
    darkness:          s.darkness || s.body || '',
    light:             s.light    || '',
    light_status:      s.light_status || 'searching',
    genre:             s.genre || '',
    tags:              s.tags  || [],
    author_id:         s.author_id,
    author_name:       s.author_name,
    created_at:        s.created_at,
    comments_disabled: s.comments_disabled || false,
    votes:             allVotes.filter(v => v.story_id === s._id).length,
    comment_count:     allComments.filter(c => c.story_id === s._id).length,
    user_voted:        userId ? (allVotes.some(v => v.story_id === s._id && v.user_id === userId) ? 1 : 0) : 0,
  }));
}

// ── Stories ───────────────────────────────────────────────
app.get('/api/stories', optAuth, async (req, res) => {
  const uid = req.user?.id || null;
  let list  = await db.stories.findAsync({});
  let out   = await enrich(list, uid);
  out.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const { q, triggers, page, limit } = req.query;
  if (q) {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    out = out.filter(s => {
      const hay = `${s.title} ${s.author_name} ${s.body} ${s.tags.join(' ')}`.toLowerCase();
      return words.every(w => hay.includes(w));
    });
  }
  if (triggers) {
    const ts = triggers.toLowerCase().split(',').map(t => t.trim()).filter(Boolean);
    out = out.filter(s => {
      const hay = `${s.title} ${s.body} ${s.tags.join(' ')}`.toLowerCase();
      return !ts.some(t => hay.includes(t));
    });
  }

  const total    = out.length;
  const pageSize = Math.min(parseInt(limit) || 20, 100);
  const pageNum  = Math.max(1, parseInt(page) || 1);
  const pages    = Math.ceil(total / pageSize) || 1;
  out = out.slice((pageNum - 1) * pageSize, pageNum * pageSize);

  res.json({ stories: out, total, page: pageNum, pages });
});

app.get('/api/stories/:id', optAuth, async (req, res) => {
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  const [out] = await enrich([story], req.user?.id || null);
  res.json(out);
});

app.get('/api/my-stories', requireAuth, async (req, res) => {
  const list = await db.stories.findAsync({ author_id: req.user.id });
  const out  = await enrich(list, req.user.id);
  out.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(out);
});

app.post('/api/stories', optAuth, async (req, res) => {
  const { title, genre, tags, darkness, light, light_status, comments_disabled, anon_name } = req.body || {};
  if (!title?.trim() || !darkness?.trim())
    return res.status(400).json({ error: 'Title and story are required' });
  const author_id   = req.user?.id || null;
  const author_name = req.user ? req.user.username : (anon_name?.trim().slice(0, 30) || 'Anonymous');
  const body = [darkness, light].filter(Boolean).join('\n\n');
  const s = await db.stories.insertAsync({
    title: title.trim(), body,
    darkness: darkness.trim(),
    light: (light || '').trim(),
    light_status: light_status || 'searching',
    genre: genre || '', tags: tags || [],
    comments_disabled: comments_disabled ? true : false,
    author_id, author_name,
    created_at: new Date().toISOString(),
  });
  res.json({ id: s._id });
});

app.patch('/api/stories/:id/toggle-comments', requireAuth, async (req, res) => {
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  if (story.author_id !== req.user.id && !req.user.is_admin)
    return res.status(403).json({ error: 'Forbidden' });
  const newVal = !story.comments_disabled;
  await db.stories.updateAsync({ _id: req.params.id }, { $set: { comments_disabled: newVal } }, {});
  res.json({ comments_disabled: newVal });
});

app.patch('/api/stories/:id', requireAuth, async (req, res) => {
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  if (story.author_id !== req.user.id && !req.user.is_admin)
    return res.status(403).json({ error: 'Forbidden' });
  const { title, genre, tags, darkness, light, light_status, comments_disabled } = req.body || {};
  if (!title?.trim() || !darkness?.trim())
    return res.status(400).json({ error: 'Title and story are required' });
  const body = [darkness, light].filter(Boolean).join('\n\n');
  await db.stories.updateAsync({ _id: req.params.id }, { $set: {
    title: title.trim(), body,
    darkness: darkness.trim(),
    light: (light || '').trim(),
    light_status: light_status || 'searching',
    genre: genre || '', tags: tags || [],
    comments_disabled: comments_disabled ? true : false,
    updated_at: new Date().toISOString(),
  }}, {});
  res.json({ id: req.params.id });
});

app.delete('/api/stories/:id', requireAuth, async (req, res) => {
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  if (story.author_id !== req.user.id && !req.user.is_admin)
    return res.status(403).json({ error: 'Forbidden' });
  await Promise.all([
    db.votes.removeAsync(   { story_id: req.params.id }, { multi: true }),
    db.comments.removeAsync({ story_id: req.params.id }, { multi: true }),
    db.stories.removeAsync( { _id: req.params.id },      {}),
  ]);
  res.json({ ok: true });
});

// ── Votes ─────────────────────────────────────────────────
app.post('/api/stories/:id/vote', requireAuth, async (req, res) => {
  const { id: sid } = req.params, uid = req.user.id;
  const existing = await db.votes.findOneAsync({ user_id: uid, story_id: sid });
  if (existing) {
    await db.votes.removeAsync({ user_id: uid, story_id: sid }, {});
    res.json({ voted: false });
  } else {
    await db.votes.insertAsync({ user_id: uid, story_id: sid });
    res.json({ voted: true });
  }
});

// ── Comments ──────────────────────────────────────────────
app.get('/api/stories/:id/comments', async (req, res) => {
  const list = await db.comments.findAsync({ story_id: req.params.id });
  list.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  res.json(list.map(c => ({ ...c, id: c._id })));
});

app.post('/api/stories/:id/comments', optAuth, async (req, res) => {
  const { body, anon_name } = req.body || {};
  if (!body?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  if (story.comments_disabled) return res.status(403).json({ error: 'Comments are disabled on this story' });
  const username = req.user ? req.user.username : (anon_name?.trim().slice(0, 30) || 'Anonymous');
  const c = await db.comments.insertAsync({
    story_id: req.params.id,
    user_id: req.user?.id || null,
    username, body: body.trim(),
    created_at: new Date().toISOString(),
  });
  res.json({ ...c, id: c._id });
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  const c = await db.comments.findOneAsync({ _id: req.params.id });
  if (!c) return res.status(404).json({ error: 'Not found' });
  if (c.user_id !== req.user.id && !req.user.is_admin)
    return res.status(403).json({ error: 'Forbidden' });
  await db.comments.removeAsync({ _id: req.params.id }, {});
  res.json({ ok: true });
});


// ── Reports ───────────────────────────────────────────────
app.post('/api/stories/:id/report', requireAuth, async (req, res) => {
  const { reason } = req.body || {};
  const story = await db.stories.findOneAsync({ _id: req.params.id });
  if (!story) return res.status(404).json({ error: 'Not found' });
  const existing = await db.reports.findOneAsync({ target_id: req.params.id, reporter_id: req.user.id });
  if (existing) return res.status(409).json({ error: 'Already reported' });
  await db.reports.insertAsync({
    type: 'story', target_id: req.params.id,
    target_title: story.title, target_author: story.author_name,
    reporter_id: req.user.id, reporter_name: req.user.username,
    reason: reason?.trim() || '',
    created_at: new Date().toISOString(), resolved: false,
  });
  res.json({ ok: true });
});

app.post('/api/comments/:id/report', requireAuth, async (req, res) => {
  const { reason } = req.body || {};
  const comment = await db.comments.findOneAsync({ _id: req.params.id });
  if (!comment) return res.status(404).json({ error: 'Not found' });
  const existing = await db.reports.findOneAsync({ target_id: req.params.id, reporter_id: req.user.id });
  if (existing) return res.status(409).json({ error: 'Already reported' });
  await db.reports.insertAsync({
    type: 'comment', target_id: req.params.id,
    target_body: comment.body.slice(0, 100),
    target_author: comment.username,
    story_id: comment.story_id,
    reporter_id: req.user.id, reporter_name: req.user.username,
    reason: reason?.trim() || '',
    created_at: new Date().toISOString(), resolved: false,
  });
  res.json({ ok: true });
});

app.get('/api/admin/reports', requireAuth, requireAdmin, async (req, res) => {
  const list = await db.reports.findAsync({ resolved: false });
  list.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(list.map(r => ({ ...r, id: r._id })));
});

app.delete('/api/admin/reports/:id', requireAuth, requireAdmin, async (req, res) => {
  await db.reports.updateAsync({ _id: req.params.id }, { $set: { resolved: true } }, {});
  res.json({ ok: true });
});

app.delete('/api/admin/reports/:id/delete-content', requireAuth, requireAdmin, async (req, res) => {
  const report = await db.reports.findOneAsync({ _id: req.params.id });
  if (!report) return res.status(404).json({ error: 'Not found' });
  if (report.type === 'story') {
    await Promise.all([
      db.votes.removeAsync(   { story_id: report.target_id }, { multi: true }),
      db.comments.removeAsync({ story_id: report.target_id }, { multi: true }),
      db.stories.removeAsync( { _id: report.target_id },      {}),
    ]);
  } else {
    await db.comments.removeAsync({ _id: report.target_id }, {});
  }
  await db.reports.updateAsync({ target_id: report.target_id }, { $set: { resolved: true } }, { multi: true });
  res.json({ ok: true });
});

// ── Admin ─────────────────────────────────────────────────
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { q, page, limit } = req.query;
  const pageSize = Math.min(parseInt(limit) || 25, 100);
  const pageNum  = Math.max(1, parseInt(page) || 1);
  const offset   = (pageNum - 1) * pageSize;

  const query = {};
  if (q?.trim()) {
    // Escape regex special chars to prevent ReDoS
    const safe = q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re   = new RegExp(safe, 'i');
    query.$or  = [{ username: re }, { email: re }];
  }

  const [total, list] = await Promise.all([
    db.users.countAsync(query),
    db.users.find(query).sort({ joined: -1 }).skip(offset).limit(pageSize).execAsync(),
  ]);

  // Only count stories for users on this page — not the entire table
  const userIds  = list.map(u => u._id);
  const stories  = userIds.length ? await db.stories.findAsync({ author_id: { $in: userIds } }) : [];
  const countMap = {};
  stories.forEach(s => { countMap[s.author_id] = (countMap[s.author_id] || 0) + 1; });

  res.json({
    users: list.map(u => ({
      id: u._id, username: u.username, is_admin: u.is_admin,
      email: u.email || '', joined: u.joined,
      story_count: countMap[u._id] || 0,
    })),
    total,
    page: pageNum,
    pages: Math.ceil(total / pageSize) || 1,
  });
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'Cannot delete your own account' });
  await Promise.all([
    db.votes.removeAsync(   { user_id:   req.params.id }, { multi: true }),
    db.comments.removeAsync({ user_id:   req.params.id }, { multi: true }),
    db.stories.removeAsync( { author_id: req.params.id }, { multi: true }),
    db.users.removeAsync(   { _id:       req.params.id }, {}),
  ]);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/promote', requireAuth, requireAdmin, async (req, res) => {
  await db.users.updateAsync({ _id: req.params.id }, { $set: { is_admin: 1 } }, {});
  res.json({ ok: true });
});

// Admin: set a user's password directly (placeholder until email flow is added)
app.patch('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { new_password } = req.body || {};
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const hash = bcrypt.hashSync(new_password, 10);
  await db.users.updateAsync({ _id: req.params.id }, { $set: { password: hash } }, {});
  res.json({ ok: true });
});

// ── Password Reset ────────────────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  // Always 200 — don't reveal whether the email exists
  if (!email?.trim() || !resend) return res.json({ ok: true });

  const user = await db.users.findOneAsync({ email: email.trim().toLowerCase() });
  if (!user?.email) return res.json({ ok: true });

  const token     = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  await db.reset_tokens.removeAsync({ user_id: user._id }, { multi: true });
  await db.reset_tokens.insertAsync({ user_id: user._id, token, expires_at });

  const appUrl    = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
  const resetLink = `${appUrl}/?reset=${token}`;

  await resend.emails.send({
    from:    process.env.RESEND_FROM || 'StoryLab <onboarding@resend.dev>',
    to:      user.email,
    subject: 'Reset your StoryLab password',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
        <h2 style="color:#1a0a00">Reset your password</h2>
        <p>Hi <strong>${user.username}</strong>,</p>
        <p>Someone requested a password reset for your StoryLab account. Click the button below to set a new password.</p>
        <p style="margin:2rem 0">
          <a href="${resetLink}" style="display:inline-block;padding:12px 28px;background:#c8a96e;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">Reset my password</a>
        </p>
        <p style="color:#888;font-size:.85em">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:2rem 0">
        <p style="color:#aaa;font-size:.8em">— The StoryLab team</p>
      </div>
    `,
  });

  res.json({ ok: true });
});

app.post('/api/reset-password', async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password || new_password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const record = await db.reset_tokens.findOneAsync({ token });
  if (!record) return res.status(400).json({ error: 'Invalid or expired reset link' });
  if (new Date(record.expires_at) < new Date())
    return res.status(400).json({ error: 'Reset link has expired — please request a new one' });

  const hash = bcrypt.hashSync(new_password, 10);
  await db.users.updateAsync({ _id: record.user_id }, { $set: { password: hash } }, {});
  await db.reset_tokens.removeAsync({ token }, {});
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  StoryLab is running on port ${PORT}\n`);
});
