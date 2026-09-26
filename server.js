/**
 * ============================================================================
 * VAULT: Fault-Tolerant Distributed Object Storage Engine (PoC)
 * ============================================================================
 * Architecture inspired by Amazon S3 & distributed block stores.
 * Simulates a 3-node distributed storage cluster on a single machine.
 *
 * Core Capabilities:
 *  1. Virtual Node topology with live heartbeat & crash simulation.
 *  2. Object splitting into discrete chunks with cryptographic SHA-256 hashes.
 *  3. Dynamic active-node replication (n-way replication factor across active nodes).
 *  4. Resilient reassembly with automatic failover upon node crash or bit-rot corruption.
 *  5. Complete telemetry & admin controls via REST API.
 * ============================================================================
 */

const express = require('express');
const multer = require('multer');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_REPO = process.env.GITHUB_REPO || 'github/gitignore';
const GITHUB_STATUS_URL = process.env.GITHUB_STATUS_URL || 'https://www.githubstatus.com/api/v2/status.json';

// Render terminates TLS at one trusted proxy; use that client IP for rate limits.
app.set('trust proxy', 1);

// Add standard security headers. CSP is disabled until inline UI scripts/styles
// are moved to external assets; COEP is disabled for the dashboard's web fonts.
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// ── Global malformed-JSON body error handler ──────────────────────────────────
// Catches SyntaxError thrown by express.json() when the client sends invalid JSON
// (e.g. an empty body, a trailing comma, or a non-JSON Content-Type).
// Without this, Express re-throws to Node's uncaughtException and the server crashes.
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: 'Malformed JSON body',
      detail: 'The request body could not be parsed as valid JSON. Check your Content-Type header and payload format.',
      hint: err.message
    });
  }
  next(err);
});

// Serve frontend static assets from public/ directory
app.use(express.static(path.join(__dirname, 'public')));

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});
const uploadRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Upload limit reached. Try again in 15 minutes.' }
});

// Bound both individual payloads and multipart parsing resources.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 1,
    fields: 5,
    parts: 6,
    fieldNameSize: 100,
    fieldSize: 16 * 1024
  }
});

// ============================================================================
// 1. VIRTUAL STORAGE NODES TOPOLOGY
// ============================================================================
const BASE_STORAGE_DIR = path.join(__dirname, 'storage');

// Maintain cluster virtual nodes with simulated disk directories and online status
const nodes = [
  {
    id: 'node_1',
    name: 'Storage Node Alpha',
    zone: 'us-east-1a',
    online: true,
    dir: path.join(BASE_STORAGE_DIR, 'node_1')
  },
  {
    id: 'node_2',
    name: 'Storage Node Beta',
    zone: 'us-east-1b',
    online: true,
    dir: path.join(BASE_STORAGE_DIR, 'node_2')
  },
  {
    id: 'node_3',
    name: 'Storage Node Gamma',
    zone: 'us-east-1c',
    online: true,
    dir: path.join(BASE_STORAGE_DIR, 'node_3')
  }
];

// ============================================================================
// ENTERPRISE DISTRIBUTED SYSTEMS CONFIGURATION & POLICIES
// ============================================================================
const clusterConfig = {
  replicationFactor: 3,
  writeQuorum: 2,         // W = 2 (Majority of 3: satisfies W + R > N)
  readQuorum: 2,          // R = 2
  autoRepairOnRead: true, // Read Repair (Self-healing on detected bit rot)
  scrubberActive: true,   // Active Anti-Entropy Scrubber daemon
  scrubberIntervalSec: 15,
  networkPartitions: []   // Array of isolated node IDs (Simulated split-brain)
};

// ============================================================================
// AUTH & USER MANAGEMENT
// ============================================================================
const USERS = [
  {
    id: 'admin',
    username: 'admin',
    passwordHash: crypto.createHash('sha256').update('admin123').digest('hex'),
    role: 'admin',
    displayName: 'System Administrator',
    email: 'admin@vault.local'
  },
  {
    id: 'user_alice',
    username: 'alice',
    passwordHash: crypto.createHash('sha256').update('demo123').digest('hex'),
    role: 'user',
    displayName: 'Alice Morgan',
    email: 'alice@vault.local'
  },
  {
    id: 'user_bob',
    username: 'bob',
    passwordHash: crypto.createHash('sha256').update('demo123').digest('hex'),
    role: 'user',
    displayName: 'Bob Singh',
    email: 'bob@vault.local'
  }
];

const authSessions = new Map();

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    role: user.role
  };
}

function createSessionToken(user) {
  const token = crypto.randomUUID();
  authSessions.set(token, {
    userId: user.id,
    expiresAt: Date.now() + (1000 * 60 * 60 * 12)
  });
  return token;
}

function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) return null;

  const session = authSessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    authSessions.delete(token);
    return null;
  }

  const user = USERS.find((entry) => entry.id === session.userId);
  if (!user) {
    authSessions.delete(token);
    return null;
  }

  return user;
}

function requireAuth(req, res, next) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access required.' });
  }
  req.user = user;
  next();
}

function canAccessFile(req, res, fileMeta) {
  if (fileMeta && (req.user.role === 'admin' || fileMeta.userId === req.user.id)) return true;
  // Do not reveal whether another user's object exists.
  res.status(404).json({ error: 'Object not found.' });
  return false;
}

function buildUserUsageSummary(userIdFilter = null) {
  const entries = Array.from(metadataStore.values());
  const filtered = userIdFilter
    ? entries.filter((item) => item.userId === userIdFilter)
    : entries;

  const totalStorageBytes = filtered.reduce((sum, item) => sum + (Number(item.size) || 0), 0);
  const totalFiles = filtered.length;

  return {
    totalStorageBytes,
    totalFiles,
    totalStorageLabel: totalStorageBytes > 0 ? formatFileSize(totalStorageBytes) : '0 B'
  };
}

function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const value = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const size = bytes / (1024 ** value);
  return `${size.toFixed(size >= 10 || value === 0 ? 0 : 1)} ${units[value]}`;
}

// Scrubber stats telemetry
const scrubberStats = {
  totalScans: 0,
  chunksVerified: 0,
  corruptionsHealed: 0,
  missingReplicasHealed: 0,
  lastScrubTimestamp: null
};

// In-Memory Concurrency Locks (Prevent race conditions on concurrent chunk mutations)
const fileLocks = new Set();
async function acquireFileLock(fileId) {
  while (fileLocks.has(fileId)) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  fileLocks.add(fileId);
}
function releaseFileLock(fileId) {
  fileLocks.delete(fileId);
}

// ============================================================================
// ACTIVE ANTI-ENTROPY SCRUBBER (BACKGROUND INTEGRITY & CONSISTENCY HEALER)
// ============================================================================
function runAntiEntropyScrubber() {
  if (!clusterConfig.scrubberActive) return { ran: false, reason: 'Scrubber disabled' };
  scrubberStats.totalScans++;
  scrubberStats.lastScrubTimestamp = new Date().toISOString();

  let checkedCount = 0;
  let healedCount = 0;
  const repairsLog = [];

  for (const fileMeta of metadataStore.values()) {
    for (const chunk of fileMeta.chunks) {
      let healthyBuffer = null;
      let healthyNodeName = null;

      // 1. Discover a verified healthy replica
      for (const nodeId of chunk.replicas) {
        const node = nodes.find((n) => n.id === nodeId);
        if (node && node.online && !clusterConfig.networkPartitions.includes(node.id)) {
          const chunkPath = path.join(node.dir, chunk.filename);
          if (fs.existsSync(chunkPath)) {
            try {
              const buf = fs.readFileSync(chunkPath);
              if (computeSha256(buf) === chunk.hash) {
                healthyBuffer = buf;
                healthyNodeName = node.name;
                break;
              }
            } catch (e) {}
          }
        }
      }

      // 2. If healthy replica exists, inspect all online nodes and heal inconsistencies
      if (healthyBuffer) {
        for (const nodeId of chunk.replicas) {
          const node = nodes.find((n) => n.id === nodeId);
          if (node && node.online && !clusterConfig.networkPartitions.includes(node.id)) {
            checkedCount++;
            const chunkPath = path.join(node.dir, chunk.filename);
            let needsRepair = false;
            let repairReason = '';

            if (!fs.existsSync(chunkPath)) {
              needsRepair = true;
              repairReason = 'Missing physical chunk file on disk partition';
              scrubberStats.missingReplicasHealed++;
            } else {
              try {
                const buf = fs.readFileSync(chunkPath);
                if (computeSha256(buf) !== chunk.hash) {
                  needsRepair = true;
                  repairReason = 'Cryptographic SHA-256 bit-rot detected';
                  scrubberStats.corruptionsHealed++;
                }
              } catch (e) {
                needsRepair = true;
                repairReason = 'Unreadable drive block';
              }
            }

            if (needsRepair) {
              try {
                fs.writeFileSync(chunkPath, healthyBuffer);
                healedCount++;
                const logMsg = `Auto-healed Chunk ${chunk.index} of "${fileMeta.originalName}" on ${node.name} (${repairReason}). Replaced with pristine replica from ${healthyNodeName}.`;
                repairsLog.push({ fileId: fileMeta.fileId, chunkIndex: chunk.index, node: node.id, reason: repairReason });
                logEvent('SCRUB_HEAL', `[SCRUBBER REPAIR] ${logMsg}`);
              } catch (e) {
                logEvent('ERROR', `Scrubber failed writing repair to ${node.name}: ${e.message}`);
              }
            }
          }
        }
      }
    }
  }

  scrubberStats.chunksVerified += checkedCount;
  if (healedCount > 0) {
    logEvent(
      'SCRUB_SUMMARY',
      `Anti-entropy sweep completed: ${checkedCount} chunks verified, ${healedCount} replica corruptions repaired.`
    );
  }

  return { ran: true, checkedCount, healedCount, repairsLog };
}

// Background anti-entropy timer (Runs every 15s)
setInterval(() => {
  try {
    runAntiEntropyScrubber();
  } catch (err) {
    console.error('Scrubber daemon exception:', err);
  }
}, clusterConfig.scrubberIntervalSec * 1000);

// Initialize directory trees for all virtual nodes on startup and recover existing disk chunks
function initializeStorageCluster() {
  if (!fs.existsSync(BASE_STORAGE_DIR)) {
    fs.mkdirSync(BASE_STORAGE_DIR, { recursive: true });
  }

  nodes.forEach((node) => {
    if (!fs.existsSync(node.dir)) {
      fs.mkdirSync(node.dir, { recursive: true });
    }
  });

  loadCatalog();

  // Reconcile and auto-discover any existing physical chunks on disk
  try {
    const discoveredFiles = new Map();
    nodes.forEach((node) => {
      if (fs.existsSync(node.dir)) {
        const files = fs.readdirSync(node.dir);
        files.forEach((f) => {
          const match = f.match(/^([a-f0-9\-]+)_chunk_([01])\.bin$/);
          if (match) {
            const fileId = match[1];
            const chunkIndex = parseInt(match[2], 10);
            if (!discoveredFiles.has(fileId)) {
              discoveredFiles.set(fileId, { chunk0: null, chunk1: null, nodes: new Set() });
            }
            const record = discoveredFiles.get(fileId);
            record.nodes.add(node.id);
            const chunkPath = path.join(node.dir, f);
            if (chunkIndex === 0 && !record.chunk0 && fs.existsSync(chunkPath)) {
              record.chunk0 = fs.readFileSync(chunkPath);
            } else if (chunkIndex === 1 && !record.chunk1 && fs.existsSync(chunkPath)) {
              record.chunk1 = fs.readFileSync(chunkPath);
            }
          }
        });
      }
    });

    for (const [fileId, rec] of discoveredFiles.entries()) {
      if (!metadataStore.has(fileId) && rec.chunk0 && rec.chunk1) {
        const buf0 = rec.chunk0;
        const buf1 = rec.chunk1;
        const totalSize = buf0.length + buf1.length;
        const formatHex = (buf) => buf.subarray(0, 16).toString('hex').match(/.{1,2}/g)?.join(' ') || '';
        const formatAscii = (buf) => buf.subarray(0, 16).toString('latin1').replace(/[^\x20-\x7E]/g, '.');

        let detectedName = `restored_object_${fileId.slice(0, 8)}.bin`;
        let detectedMime = 'application/octet-stream';
        if (buf0.subarray(0, 4).toString('ascii') === '%PDF') {
          detectedName = 'probability.pdf';
          detectedMime = 'application/pdf';
        }

        const chunk0Hash = computeSha256(buf0);
        const chunk1Hash = computeSha256(buf1);

        const restoredMeta = {
          fileId,
          originalName: detectedName,
          mimeType: detectedMime,
          size: totalSize,
          uploadedAt: new Date().toISOString(),
          replicationFactor: rec.nodes.size,
          chunks: [
            {
              index: 0,
              filename: `${fileId}_chunk_0.bin`,
              size: buf0.length,
              byteRange: [0, buf0.length - 1],
              hexPreview: formatHex(buf0),
              asciiPreview: formatAscii(buf0),
              hash: chunk0Hash,
              replicas: Array.from(rec.nodes)
            },
            {
              index: 1,
              filename: `${fileId}_chunk_1.bin`,
              size: buf1.length,
              byteRange: [buf0.length, totalSize - 1],
              hexPreview: formatHex(buf1),
              asciiPreview: formatAscii(buf1),
              hash: chunk1Hash,
              replicas: Array.from(rec.nodes)
            }
          ]
        };
        metadataStore.set(fileId, restoredMeta);
        logEvent('SYSTEM', `Discovered & re-indexed object "${detectedName}" (${fileId.slice(0, 8)}) from disk partitions.`);
      }
    }
    saveCatalog();
  } catch (err) {
    console.error('Auto-discovery error:', err);
  }

  logEvent('SYSTEM', 'Cluster initialized with 3 physical storage partitions.');
}

// In-Memory Cluster Metadata Catalog: Map of fileId -> ObjectMetadata
const metadataStore = new Map();
const CATALOG_FILE = path.join(BASE_STORAGE_DIR, 'catalog.json');

function saveCatalog() {
  try {
    const entries = Array.from(metadataStore.entries());
    fs.writeFileSync(CATALOG_FILE, JSON.stringify(entries, null, 2));
  } catch (e) {
    console.error('Failed to save catalog:', e);
  }
}

function loadCatalog() {
  try {
    if (fs.existsSync(CATALOG_FILE)) {
      const entries = JSON.parse(fs.readFileSync(CATALOG_FILE, 'utf8'));
      for (const [k, v] of entries) {
        const normalized = { ...v, userId: v.userId || 'admin' };
        metadataStore.set(k, normalized);
      }
      logEvent('SYSTEM', `Restored ${metadataStore.size} object records from cluster catalog.`);
    }
  } catch (e) {
    console.error('Failed to load catalog:', e);
  }
}

// In-Memory Event Stream for hacker-dashboard real-time telemetry
const telemetryLogs = [];

function logEvent(level, message, details = null) {
  const logEntry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    level,
    message,
    details
  };
  telemetryLogs.unshift(logEntry);
  if (telemetryLogs.length > 100) telemetryLogs.pop(); // keep last 100 logs
  console.log(`[${logEntry.timestamp}] [${level}] ${message}`);
}

// Utility: Compute SHA-256 hash of a buffer
function computeSha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function sanitizeFilename(value, fallback) {
  const filename = path.basename(String(value || ''))
    .replace(/[\u0000-\u001f\u007f"\\/]/g, '_')
    .trim()
    .slice(0, 255);
  return filename || fallback;
}

// Utility: Count chunks and compute disk usage per node
function getNodeStats(node) {
  try {
    if (!fs.existsSync(node.dir)) return { chunkCount: 0, bytesUsed: 0 };
    const files = fs.readdirSync(node.dir);
    let bytesUsed = 0;
    files.forEach((file) => {
      const stat = fs.statSync(path.join(node.dir, file));
      bytesUsed += stat.size;
    });
    return { chunkCount: files.length, bytesUsed };
  } catch (err) {
    return { chunkCount: 0, bytesUsed: 0 };
  }
}

// ============================================================================
// 2. UPLOAD & CHUNKING ENDPOINT (`POST /api/upload`)
// ============================================================================
app.post('/api/upload', requireAuth, uploadRateLimit, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file supplied for upload.' });
    }

    // Check cluster write quorum (W=2 by default): must reach quorum to confirm durable write
    const reachableNodes = nodes.filter((n) => n.online && !clusterConfig.networkPartitions.includes(n.id));
    if (reachableNodes.length < clusterConfig.writeQuorum) {
      logEvent('ERROR', `Upload rejected: Write Quorum not met (${reachableNodes.length}/${clusterConfig.writeQuorum} nodes reachable).`);
      return res.status(503).json({
        error: 'Write Quorum Failure',
        details: `Cluster durability policy requires ${clusterConfig.writeQuorum} reachable nodes, but only ${reachableNodes.length} are currently available.`,
        reachableNodes: reachableNodes.map((n) => n.id),
        writeQuorumRequired: clusterConfig.writeQuorum
      });
    }

    const fileBuffer = req.file.buffer;
    const totalSize = fileBuffer.length;
    const fileId = crypto.randomUUID();
    const originalName = sanitizeFilename(req.file.originalname, `object_${fileId.slice(0, 8)}.bin`);
    const mimeType = req.file.mimetype || 'application/octet-stream';

    // Concurrency Lock: prevent race conditions on simultaneous file ingestion
    await acquireFileLock(fileId);

    try {
      // Split file into exactly 2 data chunks
      const midPoint = Math.ceil(totalSize / 2);
      const chunk0Buffer = fileBuffer.subarray(0, midPoint);
      const chunk1Buffer = fileBuffer.subarray(midPoint);

      const chunk0Hash = computeSha256(chunk0Buffer);
      const chunk1Hash = computeSha256(chunk1Buffer);

      // Format real binary hex and ASCII previews (first 16 bytes of each chunk)
      const formatHex = (buf) => buf.subarray(0, 16).toString('hex').match(/.{1,2}/g)?.join(' ') || '';
      const formatAscii = (buf) => buf.subarray(0, 16).toString('latin1').replace(/[^\x20-\x7E]/g, '.');

      const chunksDefinition = [
        {
          index: 0,
          filename: `${fileId}_chunk_0.bin`,
          size: chunk0Buffer.length,
          byteRange: [0, midPoint - 1],
          hexPreview: formatHex(chunk0Buffer),
          asciiPreview: formatAscii(chunk0Buffer),
          hash: chunk0Hash,
          buffer: chunk0Buffer,
          replicas: []
        },
        {
          index: 1,
          filename: `${fileId}_chunk_1.bin`,
          size: chunk1Buffer.length,
          byteRange: [midPoint, totalSize - 1],
          hexPreview: formatHex(chunk1Buffer),
          asciiPreview: formatAscii(chunk1Buffer),
          hash: chunk1Hash,
          buffer: chunk1Buffer,
          replicas: []
        }
      ];

      // Replicate both chunks across reachable nodes meeting Write Quorum
      chunksDefinition.forEach((chunk) => {
        reachableNodes.forEach((node) => {
          const destPath = path.join(node.dir, chunk.filename);
          fs.writeFileSync(destPath, chunk.buffer);
          chunk.replicas.push(node.id);
        });
      });

      // Strip in-memory buffers before persisting metadata in the catalog
      const metadataRecord = {
        fileId,
        userId: req.user.id,
        owner: req.user.displayName,
        originalName,
        mimeType,
        size: totalSize,
        uploadedAt: new Date().toISOString(),
        replicationFactor: reachableNodes.length,
        chunks: chunksDefinition.map((c) => ({
          index: c.index,
          filename: c.filename,
          size: c.size,
          byteRange: c.byteRange,
          hexPreview: c.hexPreview,
          asciiPreview: c.asciiPreview,
          hash: c.hash,
          replicas: c.replicas
        }))
      };

      metadataStore.set(fileId, metadataRecord);
      saveCatalog();

      logEvent(
        'INGEST',
        `Object "${originalName}" [${totalSize} B] chunked and committed to Write Quorum (${reachableNodes.length}/${clusterConfig.writeQuorum} acks) on [${reachableNodes.map((n) => n.id).join(', ')}].`,
        { fileId, chunks: metadataRecord.chunks }
      );

      return res.status(201).json({
        success: true,
        message: 'Object successfully chunked, hashed, and replicated with quorum consistency.',
        quorumAcks: reachableNodes.length,
        writeQuorumRequired: clusterConfig.writeQuorum,
        object: metadataRecord
      });
    } finally {
      releaseFileLock(fileId);
    }
  } catch (error) {
    logEvent('ERROR', `Upload pipeline failed: ${error.message}`);
    return res.status(500).json({ error: `Internal chunking pipeline error: ${error.message}` });
  }
});

// ============================================================================
// 3. DOWNLOAD & FAULT-TOLERANT REASSEMBLY (`GET /api/download/:fileId`)
// ============================================================================
app.get('/api/download/:fileId', requireAuth, (req, res) => {
  const { fileId } = req.params;
  const fileMeta = metadataStore.get(fileId);

  if (!fileMeta) {
    return res.status(404).json({ error: `Object ID "${fileId}" not found in cluster catalog.` });
  }
  if (!canAccessFile(req, res, fileMeta)) return;

  logEvent('RETRIEVAL', `Download request received for "${fileMeta.originalName}" (${fileId}). Initiating failover-tolerant reassembly.`);

  const recoveredChunks = [];
  const retrievalDiagnostics = [];

  // Iterate sequentially over required chunks (0 and 1)
  for (const chunk of fileMeta.chunks) {
    let recoveredChunkBuffer = null;
    let successfulNodeId = null;
    const badReplicasForChunk = [];

    // Search through nodes recorded as having a replica of this chunk
    for (const nodeId of chunk.replicas) {
      const node = nodes.find((n) => n.id === nodeId);

      // Fault Tolerance Condition 1: Node offline (simulated node crash or network partition)
      if (!node || !node.online || clusterConfig.networkPartitions.includes(node.id)) {
        const isPartitioned = clusterConfig.networkPartitions.includes(node ? node.id : nodeId);
        retrievalDiagnostics.push({
          chunkIndex: chunk.index,
          nodeId,
          status: 'SKIPPED',
          reason: isPartitioned ? 'Node in isolated network partition' : 'Node is marked OFFLINE'
        });
        logEvent('WARN', `Chunk ${chunk.index} read skipped: ${node ? node.name : nodeId} is ${isPartitioned ? 'partitioned' : 'offline'}.`);
        continue;
      }

      const chunkFilePath = path.join(node.dir, chunk.filename);

      // Fault Tolerance Condition 2: File missing on disk
      if (!fs.existsSync(chunkFilePath)) {
        retrievalDiagnostics.push({
          chunkIndex: chunk.index,
          nodeId,
          status: 'MISSING',
          reason: 'Chunk file not present in drive directory'
        });
        badReplicasForChunk.push({ node, chunkFilePath });
        logEvent('WARN', `Chunk ${chunk.index} missing on disk at ${node.name}.`);
        continue;
      }

      // Read chunk from node disk
      const chunkBuffer = fs.readFileSync(chunkFilePath);

      // Fault Tolerance Condition 3: Cryptographic Integrity / Bit-Rot Check
      const actualHash = computeSha256(chunkBuffer);
      if (actualHash !== chunk.hash) {
        retrievalDiagnostics.push({
          chunkIndex: chunk.index,
          nodeId,
          status: 'CORRUPTED',
          reason: `Bit-Rot detected! Hash mismatch. Expected: ${chunk.hash.slice(0, 8)}... Actual: ${actualHash.slice(0, 8)}...`
        });
        badReplicasForChunk.push({ node, chunkFilePath });
        logEvent(
          'ALERT',
          `BIT-ROT CORRUPTION detected in Chunk ${chunk.index} on ${node.name}! Hash mismatch. Triggering failover to healthy replica.`
        );
        continue; // Failover to next replica node!
      }

      // Healthy replica found!
      recoveredChunkBuffer = chunkBuffer;
      successfulNodeId = nodeId;
      retrievalDiagnostics.push({
        chunkIndex: chunk.index,
        nodeId,
        status: 'VERIFIED',
        reason: 'SHA-256 integrity check passed'
      });
      logEvent('SUCCESS', `Chunk ${chunk.index} successfully retrieved & validated from ${node.name}.`);

      // AUTOMATIC READ REPAIR (SELF-HEALING)
      if (clusterConfig.autoRepairOnRead && badReplicasForChunk.length > 0) {
        badReplicasForChunk.forEach((bad) => {
          try {
            fs.writeFileSync(bad.chunkFilePath, recoveredChunkBuffer);
            scrubberStats.corruptionsHealed++;
            logEvent(
              'SELF_HEAL',
              `[READ REPAIR SUCCESS] Auto-healed Chunk ${chunk.index} on ${bad.node.name} using pristine replica from ${node.name}. Replica consistency restored!`
            );
          } catch (e) {
            logEvent('ERROR', `Read repair failed on ${bad.node.name}: ${e.message}`);
          }
        });
      }

      break; // Chunk recovered, proceed to next chunk
    }

    // If no replica survived for this chunk, the object is unrecoverable
    if (!recoveredChunkBuffer) {
      const failureReason = `Quorum loss: Chunk ${chunk.index} cannot be reconstructed. All candidate replica nodes are either crashed or contain corrupted data.`;
      logEvent('FATAL', failureReason, { retrievalDiagnostics });
      return res.status(503).json({
        error: 'Data Reassembly Failure',
        details: failureReason,
        diagnostics: retrievalDiagnostics
      });
    }

    recoveredChunks[chunk.index] = recoveredChunkBuffer;
  }

  // Reassemble the original object by concatenating chunk buffers in order
  const reassembledObject = Buffer.concat(recoveredChunks);

  logEvent(
    'ASSEMBLE',
    `Object "${fileMeta.originalName}" reassembled successfully (${reassembledObject.length} bytes) with 100% cryptographic integrity.`
  );

  // Return original file stream with proper download headers
  res.setHeader('Content-Type', fileMeta.mimeType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileMeta.originalName)}"`);
  res.setHeader('Content-Length', reassembledObject.length);
  res.setHeader('X-Vault-Reassembled', 'true');
  res.setHeader('X-Vault-Chunks', fileMeta.chunks.length);

  return res.send(reassembledObject);
});

// ============================================================================
// 4. ADMIN & TELEMETRY ENDPOINTS
// ============================================================================

const githubMetricsCache = { expiresAt: 0, value: null, pending: null };

async function getExternalMetrics() {
  if (githubMetricsCache.value && Date.now() < githubMetricsCache.expiresAt) {
    return githubMetricsCache.value;
  }
  if (githubMetricsCache.pending) return githubMetricsCache.pending;

  githubMetricsCache.pending = Promise.all([getGithubPlatformHealth(), getGithubRepoMetrics()])
    .then(([platformHealth, githubRepoMetrics]) => {
      githubMetricsCache.value = { platformHealth, githubRepoMetrics };
      githubMetricsCache.expiresAt = Date.now() + 60_000;
      return githubMetricsCache.value;
    })
    .finally(() => { githubMetricsCache.pending = null; });
  return githubMetricsCache.pending;
}

async function getGithubPlatformHealth() {
  try {
    const response = await fetch(GITHUB_STATUS_URL, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'Vault-Storage-Dashboard'
      }
    });

    if (!response.ok) {
      throw new Error(`GitHub status request failed with ${response.status}`);
    }

    const data = await response.json();
    const indicator = data?.status?.indicator || 'unknown';
    const description = data?.status?.description || 'GitHub status unavailable';

    return {
      source: 'GitHub Status API',
      indicator,
      description,
      updatedAt: data?.page?.updated_at || new Date().toISOString(),
      status: indicator
    };
  } catch (error) {
    return {
      source: 'GitHub Status API',
      indicator: 'unknown',
      description: 'GitHub status unavailable in offline/demo mode',
      updatedAt: new Date().toISOString(),
      status: 'unknown',
      error: error.message
    };
  }
}

async function getGithubRepoMetrics() {
  const headers = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'Vault-Storage-Dashboard'
  };

  if (GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${GITHUB_TOKEN}`;
  }

  try {
    const response = await fetch(`https://api.github.com/repos/${GITHUB_REPO}`, { headers });

    if (!response.ok) {
      throw new Error(`GitHub repo request failed with ${response.status}`);
    }

    const repo = await response.json();

    return {
      enabled: true,
      repo: repo.full_name,
      defaultBranch: repo.default_branch,
      stargazers: repo.stargazers_count,
      openIssues: repo.open_issues_count,
      watchers: repo.watchers_count,
      updatedAt: repo.updated_at
    };
  } catch (error) {
    return {
      enabled: false,
      description: 'GitHub repo metrics unavailable',
      error: error.message
    };
  }
}

app.post('/api/auth/login', loginRateLimit, (req, res) => {
  const { username, password } = req.body || {};
  const normalizedUsername = String(username || '').trim().toLowerCase();
  const suppliedHash = crypto.createHash('sha256').update(String(password || '')).digest();
  const user = USERS.find((entry) => {
    if (entry.username.toLowerCase() !== normalizedUsername) return false;
    const storedHash = Buffer.from(entry.passwordHash, 'hex');
    return storedHash.length === suppliedHash.length && crypto.timingSafeEqual(storedHash, suppliedHash);
  });
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = createSessionToken(user);
  return res.json({
    success: true,
    token,
    user: sanitizeUser(user)
  });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) authSessions.delete(token);
  return res.json({ success: true, message: 'Logged out successfully.' });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({
    success: true,
    user: sanitizeUser(req.user)
  });
});

app.get('/api/users/overview', requireAuth, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const allFiles = Array.from(metadataStore.values());
  const allUserUsage = USERS.map((user) => {
    const filesForUser = allFiles.filter((file) => file.userId === user.id);
    const totalStorageBytes = filesForUser.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
    const usagePercent = Math.min(100, ((totalStorageBytes / (1024 * 1024 * 1024)) * 100) || 0);

    return {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      files: filesForUser.length,
      totalStorageBytes: req.user.role === 'admin'
        ? totalStorageBytes
        : visibleFiles.reduce((sum, file) => sum + (Number(file.size) || 0), 0),
      totalStorageLabel: formatFileSize(totalStorageBytes),
      usagePercent: Number(usagePercent.toFixed(2))
    };
  });

  const totalStorageBytes = allUserUsage.reduce((sum, user) => sum + user.totalStorageBytes, 0);
  const usageSummary = {
    totalUsers: USERS.length,
    totalStorageBytes,
    totalFiles: allFiles.length,
    adminAccess: isAdmin,
    users: allUserUsage,
    totalStorageLabel: formatFileSize(totalStorageBytes)
  };

  if (!isAdmin) {
    return res.json({
      success: true,
      overview: {
        ...usageSummary,
        users: allUserUsage.filter((user) => user.id === req.user.id)
      },
      user: sanitizeUser(req.user)
    });
  }

  return res.json({
    success: true,
    overview: usageSummary,
    user: sanitizeUser(req.user)
  });
});

// GET /api/status - Cluster health, node telemetry, catalog, and event logs
app.get('/api/status', requireAuth, async (req, res) => {
  const nodeStats = nodes.map((node) => {
    const stats = getNodeStats(node);
    return {
      id: node.id,
      name: node.name,
      zone: node.zone,
      online: node.online,
      chunkCount: stats.chunkCount,
      bytesUsed: stats.bytesUsed
    };
  });

  const allFiles = Array.from(metadataStore.values());
  const visibleFiles = req.user.role === 'admin' ? allFiles : allFiles.filter((file) => file.userId === req.user.id);
  const activeNodesCount = nodes.filter((n) => n.online).length;
  const totalStorageBytes = nodeStats.reduce((sum, n) => sum + n.bytesUsed, 0);
  const { platformHealth, githubRepoMetrics } = await getExternalMetrics();
  const overview = {
    totalUsers: USERS.length,
    totalStorageBytes: allFiles.reduce((sum, file) => sum + (Number(file.size) || 0), 0),
    totalFiles: allFiles.length,
    totalStorageLabel: formatFileSize(allFiles.reduce((sum, file) => sum + (Number(file.size) || 0), 0)),
    users: USERS.map((user) => {
      const filesForUser = allFiles.filter((file) => file.userId === user.id);
      const bytes = filesForUser.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
      return {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        role: user.role,
        files: filesForUser.length,
        totalStorageBytes: bytes,
        totalStorageLabel: formatFileSize(bytes),
        usagePercent: Number(Math.min(100, (bytes / (1024 * 1024 * 1024)) * 100 || 0).toFixed(2))
      };
    })
  };
  if (req.user.role !== 'admin') {
    overview.totalUsers = 1;
    overview.totalStorageBytes = visibleFiles.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
    overview.totalFiles = visibleFiles.length;
    overview.totalStorageLabel = formatFileSize(overview.totalStorageBytes);
    overview.users = overview.users.filter((user) => user.id === req.user.id);
  }

  return res.json({
    auth: { user: sanitizeUser(req.user) },
    overview,
    cluster: {
      status: activeNodesCount === 0 ? 'CRITICAL_DOWN' : activeNodesCount < clusterConfig.writeQuorum ? 'DEGRADED' : 'HEALTHY',
      totalNodes: nodes.length,
      activeNodes: activeNodesCount,
      totalObjects: visibleFiles.length,
      totalStorageBytes,
      writeQuorum: clusterConfig.writeQuorum,
      readQuorum: clusterConfig.readQuorum,
      autoRepairOnRead: clusterConfig.autoRepairOnRead,
      scrubberActive: clusterConfig.scrubberActive,
      networkPartitions: req.user.role === 'admin' ? clusterConfig.networkPartitions : []
    },
    config: req.user.role === 'admin' ? clusterConfig : undefined,
    scrubber: req.user.role === 'admin' ? scrubberStats : undefined,
    nodes: nodeStats,
    files: visibleFiles,
    platformHealth,
    githubRepoMetrics,
    telemetry: req.user.role === 'admin' ? telemetryLogs.slice(0, 30) : []
  });
});

// POST /api/node/:id/toggle - Simulate hardware crash or node recovery
app.post('/api/node/:id/toggle', requireAdmin, (req, res) => {
  const { id } = req.params;
  const node = nodes.find((n) => n.id === id);

  if (!node) {
    return res.status(404).json({ error: `Node "${id}" does not exist in cluster topology.` });
  }

  node.online = !node.online;
  const statusStr = node.online ? 'RECOVERED (ONLINE)' : 'CRASHED (OFFLINE)';
  const level = node.online ? 'RECOVERY' : 'CHAOS';

  logEvent(level, `Admin intervention: ${node.name} [${node.id}] switched to ${statusStr}.`);

  return res.json({
    success: true,
    message: `Node ${node.id} is now ${node.online ? 'online' : 'offline'}.`,
    node: {
      id: node.id,
      name: node.name,
      online: node.online
    }
  });
});

// POST /api/node/:id/corrupt/:fileId/:chunkIndex - Simulate Bit Rot / Data Corruption on a specific node
// (Bonus Hackathon Feature: Live demo of cryptographic integrity check & failover!)
app.post('/api/node/:id/corrupt/:fileId/:chunkIndex', requireAdmin, (req, res) => {
  const { id, fileId, chunkIndex } = req.params;
  const node = nodes.find((n) => n.id === id);

  if (!node) {
    return res.status(404).json({ error: `Node "${id}" not found.` });
  }

  const chunkFilename = `${fileId}_chunk_${chunkIndex}.bin`;
  const chunkFilePath = path.join(node.dir, chunkFilename);

  if (!fs.existsSync(chunkFilePath)) {
    return res.status(404).json({ error: `Chunk "${chunkFilename}" does not exist on ${node.name}.` });
  }

  try {
    // Invert the first byte to trigger bit rot
    const buf = fs.readFileSync(chunkFilePath);
    if (buf.length > 0) {
      buf[0] = buf[0] ^ 0xff; // bitwise inversion
      fs.writeFileSync(chunkFilePath, buf);
    }

    logEvent('CHAOS', `Bit-rot simulated on ${node.name} for chunk ${chunkIndex} of object ${fileId.slice(0, 8)}...`);

    return res.json({
      success: true,
      message: `Bit rot simulated on ${node.name} for chunk ${chunkIndex}. SHA-256 hash now corrupt. Reassembly will failover!`
    });
  } catch (err) {
    return res.status(500).json({ error: `Failed to inject corruption: ${err.message}` });
  }
});

// POST /api/config - Configure replication, quorum, and self-healing policies
app.post('/api/config', requireAdmin, (req, res) => {
  const { writeQuorum, readQuorum, autoRepairOnRead, scrubberActive, scrubberIntervalSec } = req.body;
  if (writeQuorum !== undefined) clusterConfig.writeQuorum = Math.max(1, Math.min(3, parseInt(writeQuorum, 10)));
  if (readQuorum !== undefined) clusterConfig.readQuorum = Math.max(1, Math.min(3, parseInt(readQuorum, 10)));
  if (autoRepairOnRead !== undefined) clusterConfig.autoRepairOnRead = Boolean(autoRepairOnRead);
  if (scrubberActive !== undefined) clusterConfig.scrubberActive = Boolean(scrubberActive);
  if (scrubberIntervalSec !== undefined) clusterConfig.scrubberIntervalSec = Math.max(5, parseInt(scrubberIntervalSec, 10));

  logEvent('CONFIG', `Durability policy updated: WriteQuorum=${clusterConfig.writeQuorum}, ReadQuorum=${clusterConfig.readQuorum}, AutoRepair=${clusterConfig.autoRepairOnRead}, Scrubber=${clusterConfig.scrubberActive}`);
  return res.json({ success: true, config: clusterConfig });
});

// POST /api/cluster/scrub - Trigger immediate on-demand background integrity scrub
app.post('/api/cluster/scrub', requireAdmin, (req, res) => {
  const result = runAntiEntropyScrubber();
  return res.json({
    success: true,
    message: `Anti-entropy integrity sweep finished. Verified ${result.checkedCount} chunks, auto-repaired ${result.healedCount} replica corruptions.`,
    stats: scrubberStats,
    repairs: result.repairsLog
  });
});

// POST /api/cluster/partition/:nodeId - Simulate network partition (isolated network zone / split-brain)
app.post('/api/cluster/partition/:nodeId', requireAdmin, (req, res) => {
  const { nodeId } = req.params;
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return res.status(404).json({ error: 'Node not found' });

  const idx = clusterConfig.networkPartitions.indexOf(nodeId);
  let partitioned = false;
  if (idx >= 0) {
    clusterConfig.networkPartitions.splice(idx, 1);
    partitioned = false;
    logEvent('NETWORK', `Network partition healed for ${node.name} [${nodeId}]. Reconnected to cluster mesh.`);
  } else {
    clusterConfig.networkPartitions.push(nodeId);
    partitioned = true;
    logEvent('CHAOS', `Network partition simulated! ${node.name} [${nodeId}] isolated into unreachable network segment.`);
  }

  return res.json({
    success: true,
    nodeId,
    partitioned,
    isolatedNodes: clusterConfig.networkPartitions
  });
});

// GET /api/file/:fileId/inspect - Real-time physical disk inspection matrix across all drives
app.get('/api/file/:fileId/inspect', requireAuth, (req, res) => {
  const { fileId } = req.params;
  const fileMeta = metadataStore.get(fileId);

  if (!fileMeta) {
    return res.status(404).json({ error: `Object ${fileId} not found in catalog.` });
  }
  if (!canAccessFile(req, res, fileMeta)) return;

  const chunkInspection = fileMeta.chunks.map((chunk) => {
    const nodeReplicas = nodes.map((node) => {
      const filePath = path.join(node.dir, chunk.filename);
      const exists = fs.existsSync(filePath);
      let actualSize = 0;
      let actualHash = null;
      let hexSample = null;
      let isCorrupt = false;

      if (exists) {
        try {
          const buf = fs.readFileSync(filePath);
          actualSize = buf.length;
          actualHash = computeSha256(buf);
          hexSample = buf.subarray(0, 16).toString('hex').match(/.{1,2}/g)?.join(' ') || '';
          isCorrupt = actualHash !== chunk.hash;
        } catch (e) {
          // ignore disk read errors
        }
      }

      return {
        nodeId: node.id,
        nodeName: node.name,
        online: node.online,
        exists,
        actualSize,
        actualHash,
        hexSample,
        isCorrupt,
        isHealthy: node.online && exists && !isCorrupt
      };
    });

    return {
      index: chunk.index,
      filename: chunk.filename,
      expectedHash: chunk.hash,
      expectedSize: chunk.size,
      byteRange: chunk.byteRange || [0, 0],
      hexPreview: chunk.hexPreview || '',
      asciiPreview: chunk.asciiPreview || '',
      nodes: nodeReplicas
    };
  });

  return res.json({
    fileId: fileMeta.fileId,
    originalName: fileMeta.originalName,
    mimeType: fileMeta.mimeType,
    size: fileMeta.size,
    chunks: chunkInspection
  });
});

// GET /api/file/:fileId/trace - Interactive dry-run reassembly pipeline tracer for UI visualization
app.get('/api/file/:fileId/trace', requireAuth, (req, res) => {
  const { fileId } = req.params;
  const fileMeta = metadataStore.get(fileId);

  if (!fileMeta) {
    return res.status(404).json({ error: `Object ${fileId} not found.` });
  }
  if (!canAccessFile(req, res, fileMeta)) return;

  const traceSteps = [];
  traceSteps.push({
    type: 'INIT',
    title: `Reassembly Initiated for "${fileMeta.originalName}"`,
    detail: `Total size: ${fileMeta.size} Bytes | MIME: ${fileMeta.mimeType} | Required chunks: 2`
  });

  let reassemblyPossible = true;
  const verifiedChunks = [];

  fileMeta.chunks.forEach((chunk) => {
    traceSteps.push({
      type: 'CHUNK_REQUEST',
      chunkIndex: chunk.index,
      title: `Resolving Chunk ${chunk.index}`,
      detail: `Byte Range: [${chunk.byteRange[0]} → ${chunk.byteRange[1]}] (${chunk.size} Bytes). Expected SHA-256: ${chunk.hash.slice(0, 16)}...`
    });

    let healthyFound = false;

    for (const nodeId of chunk.replicas) {
      const node = nodes.find((n) => n.id === nodeId);
      if (!node || !node.online) {
        traceSteps.push({
          type: 'FAILOVER_OFFLINE',
          chunkIndex: chunk.index,
          nodeId,
          nodeName: node ? node.name : nodeId,
          title: `Drive ${node ? node.name : nodeId} Skipped`,
          detail: `Node is marked CRASHED/OFFLINE. Triggering dynamic failover to next replica node.`
        });
        continue;
      }

      const chunkPath = path.join(node.dir, chunk.filename);
      if (!fs.existsSync(chunkPath)) {
        traceSteps.push({
          type: 'FAILOVER_MISSING',
          chunkIndex: chunk.index,
          nodeId,
          nodeName: node.name,
          title: `Replica Missing on ${node.name}`,
          detail: `File not found on partition disk. Continuing failover hunt.`
        });
        continue;
      }

      const buf = fs.readFileSync(chunkPath);
      const computedHash = computeSha256(buf);

      if (computedHash !== chunk.hash) {
        traceSteps.push({
          type: 'FAILOVER_BITROT',
          chunkIndex: chunk.index,
          nodeId,
          nodeName: node.name,
          title: `⚠️ BIT-ROT DETECTED on ${node.name}!`,
          detail: `Cryptographic SHA-256 mismatch! Expected: ${chunk.hash.slice(0, 8)}... Actual: ${computedHash.slice(0, 8)}... Corrupted byte rejected! Auto-failing over to surviving healthy replica.`
        });
        continue;
      }

      // Healthy replica
      traceSteps.push({
        type: 'CHUNK_VERIFIED',
        chunkIndex: chunk.index,
        nodeId,
        nodeName: node.name,
        title: `✓ Chunk ${chunk.index} Verified from ${node.name}`,
        detail: `Read ${buf.length} bytes. SHA-256 verified 100%. Replicating to memory pipeline.`
      });
      healthyFound = true;
      verifiedChunks.push({ index: chunk.index, fromNode: node.name, size: buf.length });
      break;
    }

    if (!healthyFound) {
      reassemblyPossible = false;
      traceSteps.push({
        type: 'FATAL_QUORUM_LOSS',
        chunkIndex: chunk.index,
        title: `🛑 Quorum Loss on Chunk ${chunk.index}!`,
        detail: `All candidate drives are either crashed or contain corrupted bit-rot replicas. File cannot be reassembled.`
      });
    }
  });

  traceSteps.push({
    type: 'SUMMARY',
    success: reassemblyPossible,
    title: reassemblyPossible ? '🎉 Object Reassembly 100% Successful' : '❌ Reassembly Failed',
    detail: reassemblyPossible
      ? `Concatenated 2 verified binary chunks into pristine ${fileMeta.size}-byte "${fileMeta.originalName}". Zero data loss guaranteed.`
      : `Data unrecoverable under current cluster failure state.`
  });

  return res.json({
    fileId: fileMeta.fileId,
    originalName: fileMeta.originalName,
    size: fileMeta.size,
    success: reassemblyPossible,
    verifiedChunks,
    steps: traceSteps
  });
});

// Delete Object Endpoint (convenience helper for clean testing)
app.delete('/api/file/:fileId', requireAuth, (req, res) => {
  const { fileId } = req.params;
  const fileMeta = metadataStore.get(fileId);

  if (!fileMeta) {
    return res.status(404).json({ error: 'Object not found.' });
  }
  if (!canAccessFile(req, res, fileMeta)) return;

  // Delete chunk files across all physical node directories
  fileMeta.chunks.forEach((chunk) => {
    nodes.forEach((node) => {
      const p = path.join(node.dir, chunk.filename);
      if (fs.existsSync(p)) {
        try {
          fs.unlinkSync(p);
        } catch (e) {
          // ignore cleanup errors
        }
      }
    });
  });

  metadataStore.delete(fileId);
  saveCatalog();
  logEvent('PURGE', `Object "${fileMeta.originalName}" (${fileId.slice(0, 8)}) purged from cluster.`);

  return res.json({ success: true, message: `Object ${fileId} purged.` });
});

// ============================================================================
// SERVER INITIALIZATION
// ============================================================================
initializeStorageCluster();

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(` VAULT // FAULT-TOLERANT DISTRIBUTED OBJECT STORAGE CLUSTER`);
  console.log(` Node.js/Express Native Engine listening on http://localhost:${PORT}`);
  console.log(` Storage fabric ready: 3 Virtual Nodes active in ./storage/`);
  console.log(`================================================================`);
});

// Gracefully handle port-already-in-use so the process emits a clear error
// instead of throwing an unhandled 'error' event and hard-crashing.
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[FATAL] Port ${PORT} is already in use.`);
    console.error(`  → Kill the existing process:  npx kill-port ${PORT}`);
    console.error(`  → Or set a different port:    PORT=3001 node server.js`);
  } else {
    console.error('[FATAL] Server error:', err);
  }
  process.exit(1);
});

// Catch-all error handler: returns JSON for any unhandled Express route errors
app.use((err, req, res, _next) => {
  console.error('[UNHANDLED_ERROR]', err);
  if (!res.headersSent) {
    const status = err.status || 500;
    const isClientError = status >= 400 && status < 500;
    res.status(status).json({
      error: isClientError ? err.message : 'Internal server error',
      code: err.code || (status === 413 ? 'PAYLOAD_TOO_LARGE' : 'INTERNAL_ERROR')
    });
  }
});
