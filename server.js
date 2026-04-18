require('dotenv').config();
const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const ffmpeg = require('fluent-ffmpeg');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));

const client = new Anthropic();
const MAX_FRAMES = 3;
const RETURN_THRESHOLD_MINUTES = 30;

// ─── Database setup ────────────────────────────────────────────────────────
const db = new Database('security.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT,
    first_seen TEXT,
    last_seen TEXT,
    last_camera TEXT,
    times_seen INTEGER DEFAULT 1,
    flagged INTEGER DEFAULT 0,
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER,
    camera_id TEXT,
    timestamp TEXT,
    incident INTEGER DEFAULT 0,
    severity TEXT,
    description TEXT,
    is_return INTEGER DEFAULT 0,
    FOREIGN KEY(person_id) REFERENCES people(id)
  );

  CREATE TABLE IF NOT EXISTS restricted_zones (
    camera_id TEXT PRIMARY KEY
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id TEXT,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    person_ids TEXT,
    timestamp TEXT,
    webhook_sent INTEGER DEFAULT 0
  );
`);

// ─── Camera state ──────────────────────────────────────────────────────────
const cameraFeeds = {};

// ─── Email transporter ─────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// ─── Helpers ───────────────────────────────────────────────────────────────
function getOtherCameraContext(currentCameraId) {
  return Object.entries(cameraFeeds)
    .filter(([id]) => id !== currentCameraId)
    .map(([id, feed]) => {
      if (!feed.lastIncident) return `Camera ${id}: No recent incidents.`;
      const i = feed.lastIncident;
      return `Camera ${id}: ${i.description} (type: ${i.type}, severity: ${i.severity}, time: ${i.time})`;
    })
    .join('\n') || 'No activity on other cameras yet.';
}

function isRestrictedZone(cameraId) {
  return !!db.prepare('SELECT 1 FROM restricted_zones WHERE camera_id = ?').get(cameraId);
}

function isReturningPerson(personId) {
  const person = db.prepare('SELECT last_seen FROM people WHERE id = ?').get(personId);
  if (!person || !person.last_seen) return false;
  const minutesAgo = (new Date() - new Date(person.last_seen)) / 1000 / 60;
  return minutesAgo >= RETURN_THRESHOLD_MINUTES;
}

function getDaysSinceFirstSeen(personId) {
  const person = db.prepare('SELECT first_seen FROM people WHERE id = ?').get(personId);
  if (!person) return 0;
  return Math.floor((new Date() - new Date(person.first_seen)) / 1000 / 60 / 60 / 24);
}

function getMovementTimeline(personId) {
  return db.prepare(`
    SELECT camera_id, timestamp, incident, severity
    FROM sightings WHERE person_id = ?
    ORDER BY timestamp DESC LIMIT 20
  `).all(personId);
}

// ─── Alert logger ──────────────────────────────────────────────────────────
function logAlert(cameraId, alertType, severity, description, personIds = [], webhookSent = false) {
  db.prepare(`
    INSERT INTO alerts (camera_id, alert_type, severity, description, person_ids, timestamp, webhook_sent)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    cameraId,
    alertType,
    severity,
    description,
    JSON.stringify(personIds),
    new Date().toISOString(),
    webhookSent ? 1 : 0
  );
}

// ─── Webhook sender ────────────────────────────────────────────────────────
async function sendWebhook(payload) {
  const webhookUrl = process.env.DASHBOARD_WEBHOOK_URL;
  if (!webhookUrl) {
    console.log('[Webhook] No DASHBOARD_WEBHOOK_URL set — skipping.');
    return false;
  }

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    console.log(`[Webhook] Sent: ${payload.alert_type} from ${payload.camera_id}`);
    return true;

  } catch (err) {
    console.error('[Webhook] Error:', err.message);
    return false;
  }
}

// ─── Email sender ──────────────────────────────────────────────────────────
function sendEmail(subject, htmlBody, imageBase64, cameraId) {
  const mailOptions = {
    from: `AI Security Monitor <chris@fastmanacollective.com>`,
    to: process.env.ALERT_EMAIL,
    subject,
    html: htmlBody,
    attachments: [{
      filename: `snapshot-${cameraId}.jpg`,
      content: Buffer.from(imageBase64, 'base64'),
      contentType: 'image/jpeg',
      cid: 'snapshot'
    }]
  };
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) console.error('Email error:', err.message);
    else console.log('Alert email sent:', info.response);
  });
}

// ─── IP camera frame capture ───────────────────────────────────────────────
app.post('/capture-ip-camera', async (req, res) => {
  const { streamUrl } = req.body;
  const outputPath = path.join(__dirname, `tmp-${Date.now()}.jpg`);
  try {
    await new Promise((resolve, reject) => {
      ffmpeg(streamUrl).frames(1).output(outputPath)
        .on('end', resolve).on('error', reject).run();
    });
    const imageData = fs.readFileSync(outputPath).toString('base64');
    fs.unlinkSync(outputPath);
    res.json({ image: imageData });
  } catch (err) {
    res.status(500).json({ error: 'Could not capture frame: ' + err.message });
  }
});

// ─── Main analysis endpoint ────────────────────────────────────────────────
app.post('/analyze', async (req, res) => {
  try {
    const { image, cameraId } = req.body;
    if (!cameraId) return res.status(400).json({ error: 'cameraId is required' });

    if (!cameraFeeds[cameraId]) {
      cameraFeeds[cameraId] = { frames: [], lastIncident: null };
    }

    cameraFeeds[cameraId].frames.push(image);
    if (cameraFeeds[cameraId].frames.length > MAX_FRAMES) {
      cameraFeeds[cameraId].frames.shift();
    }

    const recentFrames = cameraFeeds[cameraId].frames;
    const otherCameraContext = getOtherCameraContext(cameraId);
    const restricted = isRestrictedZone(cameraId);

    const knownPeople = db.prepare(
      'SELECT * FROM people ORDER BY last_seen DESC LIMIT 20'
    ).all();

    const peopleContext = knownPeople.length > 0
      ? knownPeople.map(p =>
          `Person #${p.id}: "${p.description}" — first seen ${p.first_seen}, last on ${p.last_camera} at ${p.last_seen}, seen ${p.times_seen} times.${p.flagged ? ' ⚠️ FLAGGED.' : ''}${p.notes ? ` Notes: ${p.notes}` : ''}`
        ).join('\n')
      : 'No people recorded yet.';

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          ...recentFrames.map((frame, i) => ([
            {
              type: 'text',
              text: `Camera ${cameraId} — Frame ${i + 1} of ${recentFrames.length} (${
                i === recentFrames.length - 1 ? 'most recent'
                : `${(recentFrames.length - 1 - i) * 5} seconds ago`
              }):`
            },
            { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: frame } }
          ])).flat(),
          {
            type: 'text',
            text: `You are a multi-camera security AI analyzing camera ${cameraId}.
${restricted ? '⚠️ THIS IS A RESTRICTED ZONE. Flag any unknown person immediately.' : ''}

KNOWN PEOPLE DATABASE:
${peopleContext}

Recent activity on OTHER cameras:
${otherCameraContext}

Analyze the ${recentFrames.length} frame(s) from camera ${cameraId}.
For each visible person:
- Match to KNOWN PEOPLE DATABASE if possible
- If matched, use their person_id and set is_new to false
- If new/unknown, describe clearly and set is_new to true

Flag any of the following:
- People looking distressed or arguing
- Unusual crowding or movement
- Anyone appearing to need help
- Situations escalating between frames
- People moving between cameras
${restricted ? '- ANY unknown person in this restricted zone' : ''}

Severity: LOW / MEDIUM / HIGH

Respond ONLY with raw JSON, no markdown:
{
  "incident": true or false,
  "type": "what you see or null",
  "confidence": "high, medium, or low",
  "severity": "LOW, MEDIUM, or HIGH, or null",
  "description": "one sentence summary",
  "crossCamera": true or false,
  "crossCameraNote": "movement between cameras or null",
  "people": [
    {
      "person_id": existing id as integer or null,
      "description": "detailed appearance",
      "is_new": true or false
    }
  ]
}`
          }
        ]
      }]
    });

    const raw = response.content[0].text.replace(/```json|```/g, '').trim();
    console.log(`[Camera ${cameraId}] Claude:`, raw);
    const result = JSON.parse(raw);

    const now = new Date().toISOString();
    const resolvedPeople = [];
    const behavioralAlerts = [];

    // ── People database + behavioral analysis ──────────────────────────────
    if (result.people && Array.isArray(result.people)) {
      for (const person of result.people) {
        let personId = person.person_id;
        let isReturn = false;

        if (person.is_new || !personId) {
          const info = db.prepare(`
            INSERT INTO people (description, first_seen, last_seen, last_camera, times_seen)
            VALUES (?, ?, ?, ?, 1)
          `).run(person.description, now, now, cameraId);
          personId = info.lastInsertRowid;
          console.log(`[DB] New person #${personId}`);

          if (restricted) {
            behavioralAlerts.push({
              type: 'RESTRICTED_ZONE',
              personId,
              message: `Unknown person detected in restricted zone on camera ${cameraId}.`,
              severity: 'HIGH'
            });
          }

        } else {
          isReturn = isReturningPerson(personId);
          const daysSinceFirst = getDaysSinceFirstSeen(personId);

          if (isReturn) {
            const p = db.prepare('SELECT * FROM people WHERE id = ?').get(personId);
            const minutesAway = Math.round(
              (new Date() - new Date(p.last_seen)) / 1000 / 60
            );
            behavioralAlerts.push({
              type: 'RETURN',
              personId,
              message: `Person #${personId} returned to camera ${cameraId} after ${minutesAway} minutes. First seen ${daysSinceFirst} day(s) ago.${p.flagged ? ' ⚠️ THIS PERSON IS FLAGGED.' : ''}`,
              severity: p.flagged ? 'HIGH' : 'LOW'
            });
          }

          db.prepare(`
            UPDATE people SET last_seen = ?, last_camera = ?, times_seen = times_seen + 1
            WHERE id = ?
          `).run(now, cameraId, personId);
        }

        db.prepare(`
          INSERT INTO sightings (person_id, camera_id, timestamp, incident, severity, description, is_return)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          personId, cameraId, now,
          result.incident ? 1 : 0,
          result.severity || null,
          result.description,
          isReturn ? 1 : 0
        );

        const personRecord = db.prepare('SELECT * FROM people WHERE id = ?').get(personId);
        resolvedPeople.push({
          ...person,
          person_id: personId,
          is_return: isReturn,
          times_seen: personRecord?.times_seen || 1,
          flagged: personRecord?.flagged || 0
        });
      }
    }

    result.people = resolvedPeople;
    result.behavioralAlerts = behavioralAlerts;

    if (result.incident) {
      cameraFeeds[cameraId].lastIncident = {
        ...result, time: new Date().toLocaleTimeString()
      };
    }

    const severityColor = { HIGH: '#cc0000', MEDIUM: '#ff8800', LOW: '#cccc00' };

    // ── Incident alert ─────────────────────────────────────────────────────
    if (result.incident && result.confidence !== 'low' && result.severity !== 'LOW') {
      const color = severityColor[result.severity] || '#333';

      const webhookPayload = {
        alert_type: 'INCIDENT',
        severity: result.severity,
        camera_id: cameraId,
        description: result.description,
        type: result.type,
        confidence: result.confidence,
        timestamp: now,
        people: resolvedPeople.map(p => ({
          person_id: p.person_id,
          description: p.description,
          is_new: p.is_new,
          is_return: p.is_return,
          times_seen: p.times_seen,
          flagged: !!p.flagged
        })),
        cross_camera: result.crossCamera || false,
        cross_camera_note: result.crossCameraNote || null,
        snapshot_base64: image
      };

      const webhookSent = await sendWebhook(webhookPayload);

      logAlert(
        cameraId, 'INCIDENT', result.severity, result.description,
        resolvedPeople.map(p => p.person_id), webhookSent
      );

      const peopleHtml = resolvedPeople.length > 0
        ? `<p><strong>People involved:</strong></p><ul>${resolvedPeople.map(p =>
            `<li>Person #${p.person_id} — ${p.description}${p.is_return ? ' <strong>(RETURNING)</strong>' : p.is_new ? ' (NEW)' : ''}</li>`
          ).join('')}</ul>` : '';

      sendEmail(
        `🚨 [${result.severity}] Camera ${cameraId}: ${result.type}`,
        `<h2 style="color:${color};">[${result.severity}] Incident on Camera ${cameraId}</h2>
         <p><strong>Type:</strong> ${result.type}</p>
         <p><strong>Severity:</strong> <span style="color:${color};font-weight:bold;">${result.severity}</span></p>
         <p><strong>Confidence:</strong> ${result.confidence}</p>
         <p><strong>Description:</strong> ${result.description}</p>
         ${result.crossCamera ? `<p><strong>⚠️ Cross-Camera:</strong> ${result.crossCameraNote}</p>` : ''}
         ${peopleHtml}
         <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
         <br/><img src="cid:snapshot" style="width:640px;"/>`,
        image, cameraId
      );
    }

    // ── Behavioral alerts ──────────────────────────────────────────────────
    for (const alert of behavioralAlerts) {
      const color = severityColor[alert.severity] || '#333';
      const timeline = getMovementTimeline(alert.personId);

      const webhookPayload = {
        alert_type: alert.type,
        severity: alert.severity,
        camera_id: cameraId,
        description: alert.message,
        timestamp: now,
        people: resolvedPeople
          .filter(p => p.person_id === alert.personId)
          .map(p => ({
            person_id: p.person_id,
            description: p.description,
            is_new: p.is_new,
            is_return: p.is_return,
            times_seen: p.times_seen,
            flagged: !!p.flagged
          })),
        cross_camera: false,
        cross_camera_note: null,
        movement_timeline: timeline,
        snapshot_base64: image
      };

      const webhookSent = await sendWebhook(webhookPayload);

      logAlert(
        cameraId, alert.type, alert.severity, alert.message,
        [alert.personId], webhookSent
      );

      const timelineHtml = timeline.length > 0
        ? `<p><strong>Movement timeline:</strong></p>
           <table border="1" cellpadding="6" style="border-collapse:collapse;font-size:12px;">
             <tr><th>Time</th><th>Camera</th><th>Status</th></tr>
             ${timeline.map(t => `
               <tr>
                 <td>${new Date(t.timestamp).toLocaleTimeString()}</td>
                 <td>${t.camera_id}</td>
                 <td style="color:${t.incident ? (severityColor[t.severity] || '#333') : 'green'}">
                   ${t.incident ? `[${t.severity}]` : 'Clear'}
                 </td>
               </tr>
             `).join('')}
           </table>` : '';

      sendEmail(
        `⚠️ [BEHAVIORAL] ${alert.type} on Camera ${cameraId}`,
        `<h2 style="color:${color};">Behavioral Alert — ${alert.type}</h2>
         <p>${alert.message}</p>
         ${timelineHtml}
         <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
         <br/><img src="cid:snapshot" style="width:640px;"/>`,
        image, cameraId
      );
    }

    res.json({ ...result, cameraId });

  } catch (err) {
    console.error('Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Status ────────────────────────────────────────────────────────────────
app.get('/status', (req, res) => {
  const restricted = db.prepare('SELECT camera_id FROM restricted_zones').all().map(r => r.camera_id);
  res.json(Object.entries(cameraFeeds).map(([id, feed]) => ({
    cameraId: id,
    frameCount: feed.frames.length,
    lastIncident: feed.lastIncident || null,
    restricted: restricted.includes(id)
  })));
});

// ─── Restricted zones ──────────────────────────────────────────────────────
app.get('/restricted-zones', (req, res) => {
  res.json(db.prepare('SELECT camera_id FROM restricted_zones').all().map(r => r.camera_id));
});

app.post('/restricted-zones/:cameraId', (req, res) => {
  const { cameraId } = req.params;
  const existing = db.prepare('SELECT 1 FROM restricted_zones WHERE camera_id = ?').get(cameraId);
  if (existing) {
    db.prepare('DELETE FROM restricted_zones WHERE camera_id = ?').run(cameraId);
    res.json({ restricted: false });
  } else {
    db.prepare('INSERT INTO restricted_zones (camera_id) VALUES (?)').run(cameraId);
    res.json({ restricted: true });
  }
});

// ─── Alerts ────────────────────────────────────────────────────────────────
app.get('/alerts', (req, res) => {
  res.json(db.prepare('SELECT * FROM alerts ORDER BY timestamp DESC').all());
});

// ─── People ────────────────────────────────────────────────────────────────
app.get('/people', (req, res) => {
  res.json(db.prepare('SELECT * FROM people ORDER BY last_seen DESC').all());
});

app.get('/people/:id/sightings', (req, res) => {
  res.json(db.prepare(
    'SELECT * FROM sightings WHERE person_id = ? ORDER BY timestamp DESC'
  ).all(req.params.id));
});

app.get('/people/:id/timeline', (req, res) => {
  res.json(getMovementTimeline(req.params.id));
});

app.post('/people/:id/notes', (req, res) => {
  db.prepare('UPDATE people SET notes = ? WHERE id = ?').run(req.body.notes, req.params.id);
  res.json({ success: true });
});

app.post('/people/:id/flag', (req, res) => {
  const person = db.prepare('SELECT flagged FROM people WHERE id = ?').get(req.params.id);
  if (!person) return res.status(404).json({ error: 'Not found' });
  const newFlag = person.flagged ? 0 : 1;
  db.prepare('UPDATE people SET flagged = ? WHERE id = ?').run(newFlag, req.params.id);
  res.json({ success: true, flagged: !!newFlag });
});

app.delete('/people/:id', (req, res) => {
  db.prepare('DELETE FROM sightings WHERE person_id = ?').run(req.params.id);
  db.prepare('DELETE FROM people WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── Start ─────────────────────────────────────────────────────────────────
app.listen(3000, () => console.log('Running on http://localhost:3000'));
