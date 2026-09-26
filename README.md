# ⬡ VAULT // Fault-Tolerant Distributed Object Storage

> **An S3-inspired, fault-tolerant distributed object storage proof-of-concept (PoC) featuring binary chunking, cryptographic SHA-256 bit-rot detection, multi-drive replication, and automated failover.**

---

## 📌 Table of Contents
- [What is Vault?](#what-is-vault)
- [Why is it Used? (The Motivation)](#why-is-it-used-the-motivation)
- [Core Architecture & How it Works](#core-architecture--how-it-works)
- [Key Features](#key-features)
- [Technical Stack](#technical-stack)
- [Getting Started & Installation](#getting-started--installation)
- [Interactive Demo Guide](#interactive-demo-guide)
- [API Reference](#api-reference)
- [Deployment (Render Free Tier)](#deployment-render-free-tier)
- [License](#license)

---

## 💡 What is Vault?

**Vault** is an architectural simulation of a distributed object store (similar to **Amazon S3**, **Ceph**, or **MinIO**), engineered to run on a single machine **without requiring Docker, Kubernetes, or complex microservice orchestrators**.

Instead of treating file uploads as monolithic blobs stored on a single drive, Vault:
1. Deconstructs incoming objects into discrete binary chunks.
2. Computes an immutable cryptographic fingerprint (**SHA-256 digest**) for each chunk.
3. Distributes and replicates these chunks across three simulated physical drives (`./storage/node_1`, `./storage/node_2`, `./storage/node_3`).
4. Reconstructs files dynamically on download by verifying cryptographic integrity, bypassing offline nodes, and surviving simulated bit-rot corruption.

---

## 🎯 Why is it Used? (The Motivation)

In enterprise cloud infrastructures, data durability and high availability are critical. Traditional monolithic file storage suffers from several fatal vulnerabilities:

### 1. Single Point of Failure (SPOF)
If a physical hard drive dies in a traditional server, any file located entirely on that disk is permanently lost. Distributed systems solve this by replicating chunks across independent hardware failure domains (racks, availability zones, or physical disks).

### 2. Silent Data Corruption ("Bit Rot")
Storage media degrade over time due to magnetic decay, electrical fluctuations, or cosmic rays, flipping single bits without the OS noticing. Vault solves this by computing a cryptographic **SHA-256 hash** at ingestion time. If a bit flips on one drive, Vault detects the hash discrepancy during reassembly, rejects the corrupt block, and fetches a healthy replica from a surviving drive.

### 3. High Availability Under Hardware Crashes
Nodes inevitably crash or reboot for maintenance. Vault guarantees zero-downtime file retrieval as long as at least one healthy replica of each chunk is online.

### 4. Educational & Hackathon Prototyping
Setting up real Ceph, GlusterFS, or AWS multi-region clusters requires substantial infrastructure, Docker daemon access, and cloud budgets. Vault demonstrates these exact distributed computing primitives in a **lightweight, native Node.js service** deployable anywhere (including Render's free tier).

---

## 🏗️ Core Architecture & How it Works

```
                                  [ CLIENT ]
                                      │
                         HTTP POST /api/upload
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   VAULT STORAGE ENGINE    │
                        │    (In-Memory Catalog)    │
                        └─────────────┬─────────────┘
                                      │
                   Split into 2 Chunks + SHA-256 Digest
                                      │
                  ┌───────────────────┴───────────────────┐
                  ▼                                       ▼
             [ Chunk 0 ]                             [ Chunk 1 ]
       SHA256: 7137cd0f...                     SHA256: 39b4338d...
                  │                                       │
                  ├───────────────────┬───────────────────┤
                  ▼                   ▼                   ▼
          ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
          │    NODE 1     │   │    NODE 2     │   │    NODE 3     │
          │    (Alpha)    │   │    (Beta)     │   │    (Gamma)    │
          │  ./storage/   │   │  ./storage/   │   │  ./storage/   │
          │    node_1/    │   │    node_2/    │   │    node_3/    │
          └───────────────┘   └───────────────┘   └───────────────┘
```

### 1. Ingestion & Chunking (`POST /api/upload`)
- The file stream is intercepted in memory via Multer.
- The binary buffer is bisected into two chunks:
  $$\text{midpoint} = \left\lceil \frac{\text{totalSize}}{2} \right\rceil$$
- An immutable SHA-256 checksum is calculated for both chunks.
- Chunks are simultaneously written to all active node directories (`./storage/node_X`).
- Object metadata (hashes, chunk sizes, replica locations) is recorded in the catalog.

### 2. Retrieval & Failover Reassembly (`GET /api/download/:fileId`)
- For each chunk (0 and 1):
  1. Identifies which nodes hold a replica.
  2. Bypasses any node marked **crashed / offline**.
  3. Reads the chunk buffer from the first online node.
  4. Recalculates the SHA-256 hash.
  5. **Integrity Check**: If the hash does not match, a **Bit-Rot Alert** is triggered and the engine immediately fails over to the next replica node.
- Reassembles the verified chunks into the original byte buffer and streams it to the user.

---

## ✨ Key Features

- **Virtual Node Topology**: Simulates 3 independent storage partitions on disk with isolated read/write failure boundaries.
- **Dynamic Active Replication**: Dynamically adjusts replication factor to match all online nodes at write time.
- **Cryptographic SHA-256 Verification**: Guarantees bit-level file integrity; corrupt data is never served to clients.
- **Interactive Chaos Engineering**: One-click simulated hardware crashes and simulated bit-rot injection directly from the UI.
- **Live Hacker Telemetry Dashboard**: Real-time event log terminal showing heartbeat checks, ingestion pipelines, failover alerts, and disk partition stats.
- **Zero External Dependencies**: Runs without Docker, PostgreSQL, Redis, or cloud storage SDKs.

---

## 🛠️ Technical Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Runtime** | Node.js (v18+) | Native JavaScript execution engine |
| **Web Server** | Express.js | REST routing, static asset serving, middleware |
| **File Ingestion** | Multer | Memory-buffered multi-part file uploads |
| **Cryptography** | Node.js `crypto` | SHA-256 hashing and UUID generation |
| **Disk I/O** | Node.js `fs` & `path` | Partition directory creation and chunk persistence |
| **Cross-Origin** | CORS | Cross-origin request headers |
| **Frontend UI** | HTML5, CSS3, Vanilla JS | Dark-themed, cyber-style telemetry dashboard |
| **Database** | In-Memory Catalog (Map) | Ephemeral metadata storage for ultra-fast lookup |

---

## � Default Login Credentials

Use the following credentials to sign in to the dashboard:

- Admin: `admin` / `admin123`
- User: `alice` / `demo123`
- User: `bob` / `demo123`

These are the default demo accounts configured for the app.

## �🚀 Getting Started & Installation

### Prerequisites
- Node.js (v18.0.0 or higher)
- npm (v9.0.0 or higher)

### 1. Clone or Open the Repository
```bash
cd promptathon
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Start the Storage Cluster
```bash
npm start
```

The cluster will initialize partitions `./storage/node_1`, `./storage/node_2`, and `./storage/node_3` and start listening on:
👉 **`http://localhost:3000`**

---

## 🎮 Interactive Demo Guide

Once the dashboard is open at `http://localhost:3000`:

### Demo 1: File Ingestion & Chunking
1. Drag and drop any file (image, PDF, text, binary) into the **Object Ingestion** box.
2. Click **"⚡ Upload & Replicate Across Active Nodes"**.
3. Inspect the **Object Catalog**: observe how the file was partitioned into `CHUNK 0` and `CHUNK 1` with individual SHA-256 hashes and replica tags across all 3 nodes.

### Demo 2: Hardware Crash & Resilient Failover
1. Under **Cluster Virtual Drives**, click **"💥 Simulate Crash"** on **Node 1 (Alpha)**.
2. The card turns red with status `CRASHED / OFFLINE`.
3. In the Object Catalog, click **"📥 Download & Reassemble"**.
4. Observe the download completes instantly and check the **Live Cluster Audit Log**:
   ```
   [WARN] Chunk 0 read skipped: Storage Node Alpha is offline.
   [SUCCESS] Chunk 0 retrieved & validated from Storage Node Beta.
   [ASSEMBLE] Object reassembled successfully with 100% cryptographic integrity.
   ```

### Demo 3: Bit-Rot Detection & Auto-Recovery
1. Recover Node 1 by clicking **"⚡ Recover Node"**.
2. On any uploaded file in the browser, find `CHUNK 0` and click **"Corrupt on 1"**.
3. This flips a physical byte on disk in Node 1's partition, intentionally corrupting its hash.
4. Click **"📥 Download & Reassemble"**.
5. Check the live terminal log:
   ```
   [ALERT] BIT-ROT CORRUPTION detected in Chunk 0 on Storage Node Alpha! Hash mismatch. Triggering failover to healthy replica.
   [SUCCESS] Chunk 0 successfully retrieved & validated from Storage Node Beta.
   ```
   *Vault successfully rejected the rotten byte and protected your file!*

---

## 📡 API Reference

### 1. Ingest Object
```http
POST /api/upload
Content-Type: multipart/form-data (field: "file")
```
**Response (201 Created):**
```json
{
  "success": true,
  "object": {
    "fileId": "9e107b95-978d-400b-b6c0-132a4dc8d170",
    "originalName": "report.pdf",
    "size": 1048576,
    "replicationFactor": 3,
    "chunks": [
      {
        "index": 0,
        "filename": "9e107b95_chunk_0.bin",
        "size": 524288,
        "hash": "7137cd0fb5ecbccbb2879a442c9a8914...",
        "replicas": ["node_1", "node_2", "node_3"]
      },
      {
        "index": 1,
        "filename": "9e107b95_chunk_1.bin",
        "size": 524288,
        "hash": "39b4338d90638cbf2e96197480528e7f...",
        "replicas": ["node_1", "node_2", "node_3"]
      }
    ]
  }
}
```

### 2. Download & Reassemble Object
```http
GET /api/download/:fileId
```
- Performs live SHA-256 integrity verification.
- Automatically handles node failovers.
- Returns the assembled binary stream with `Content-Disposition: attachment`.

### 3. Real-Time Physical Disk Inspection Matrix
```http
GET /api/file/:fileId/inspect
```
- Reads the actual physical disk partitions across all 3 nodes.
- Validates disk presence, actual file size, and recalculates real SHA-256 hashes against catalog digests.
- Emits real hex magic bytes and ASCII signatures.

### 4. Interactive Reassembly Pipeline Tracer
```http
GET /api/file/:fileId/trace
```
- Simulates the reassembly step-by-step without triggering a file download.
- Emits real-time failover diagnostic steps for offline and bit-rotted nodes.

### 5. Cluster Telemetry & Health
```http
GET /api/status
```
- Returns up/down status of all 3 nodes, disk usage stats, stored catalog records, and recent audit logs.

### 6. Toggle Node Crash / Recovery
```http
POST /api/node/:id/toggle
```
- Toggles node status between `online` and `offline`.

### 7. Simulate Bit-Rot
```http
POST /api/node/:id/corrupt/:fileId/:chunkIndex
```
- Inverts bytes in a specific chunk file on disk to simulate bit rot.

### 8. Purge Object
```http
DELETE /api/file/:fileId
```
- Deletes all chunk files across all physical partitions and clears catalog metadata.

---

## ☁️ Deployment (Render Free Tier)

The repository includes a root-level `render.yaml` Blueprint for deploying this Node.js web service. Connect the repository in the Render Dashboard and create a Blueprint to use it.

1. Push your repository to GitHub or GitLab.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** -> **Web Service**.
3. Select your repository.
4. If creating a Web Service manually, configure the settings:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
    - **Start Command**: `npm start`
   - **Plan**: `Free`
5. Click **Deploy Web Service**.

If Render logs show `Running 'node start'`, change the service's **Start Command** in **Settings → Build & Deploy** to `npm start` and redeploy. `node start` looks for a JavaScript file named `start`; this project instead defines an npm `start` script that launches `server.js`.

Render will automatically bind to `0.0.0.0` and allocate `process.env.PORT`.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
