# 🚀 ChainGuard Protocol — Complete Setup Guide

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Node.js | >= 18.0 | Frontend + Hardhat |
| Python | >= 3.11 | Backend + Agents |
| Docker | >= 24.0 | Containerized deployment |
| Redis | >= 7.0 | Agent message bus |
| PostgreSQL | >= 15 | Persistent storage |
| Git | Latest | Version control |

---

## Step 1: Clone and Initialize

```bash
git clone https://github.com/chainguard-protocol/chainguard
cd chainguard

# Create all required directories
mkdir -p logs data/redis data/postgres data/ipfs evidence quarantine
```

---

## Step 2: Environment Configuration

```bash
# Copy environment template
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# === BLOCKCHAIN RPC ENDPOINTS ===
ETH_MAINNET_RPC=https://mainnet.infura.io/v3/YOUR_KEY
ETH_SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_KEY
POLYGON_RPC=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY
ARBITRUM_RPC=https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=https://mainnet.helius-rpc.com/?api-key=YOUR_KEY

# === AI AGENT CONFIGURATION ===
ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE
AGENT_MODEL=claude-sonnet-4-20250514
AGENT_MAX_TOKENS=1000

# === THREAT INTELLIGENCE APIs ===
CHAINABUSE_API_KEY=YOUR_KEY
MISTTRACK_API_KEY=YOUR_KEY
ETHERSCAN_API_KEY=YOUR_KEY
VIRUSTOTAL_API_KEY=YOUR_KEY

# === DATABASE ===
DATABASE_URL=postgresql://chainguard:password@localhost:5432/chainguard
REDIS_URL=redis://localhost:6379

# === SMART CONTRACTS ===
THREAT_REGISTRY_ADDRESS_ETH=0x...
THREAT_REGISTRY_ADDRESS_POLYGON=0x...
REPUTATION_ORACLE_ADDRESS=0x...
INCIDENT_VAULT_ADDRESS=0x...
CHAINGUARD_SIGNER_PRIVATE_KEY=0x...  # For on-chain submissions

# === IPFS ===
IPFS_API_URL=https://ipfs.infura.io:5001
IPFS_PROJECT_ID=YOUR_KEY
IPFS_PROJECT_SECRET=YOUR_SECRET

# === BACKEND ===
SENTINEL_API_PORT=8000
SENTINEL_SECRET_KEY=generate_random_secret_here
CORS_ORIGINS=http://localhost:3000,chrome-extension://

# === SECURITY ===
QUARANTINE_DIRECTORY=/home/chainguard/quarantine
EVIDENCE_RETENTION_DAYS=90
AUTO_QUARANTINE_ENABLED=true
MAX_RISK_SCORE_BEFORE_BLOCK=70

# === MONITORING ===
PROMETHEUS_PORT=9090
GRAFANA_PORT=3001
LOG_LEVEL=INFO
```

---

## Step 3: Install Dependencies

### 3.1 Python Backend + Agents
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# OR: venv\Scripts\activate  # Windows

# Install all Python dependencies
pip install -r requirements.txt
```

**requirements.txt:**
```
fastapi==0.111.0
uvicorn[standard]==0.29.0
websockets==12.0
redis[hiredis]==5.0.4
sqlalchemy==2.0.30
asyncpg==0.29.0
alembic==1.13.1
pydantic==2.7.1
anthropic==0.26.0
langchain==0.2.3
langchain-anthropic==0.1.15
web3==6.19.0
eth-abi==5.1.0
solana==0.34.3
httpx==0.27.0
aiohttp==3.9.5
python-multipart==0.0.9
python-dotenv==1.0.1
cryptography==42.0.8
pycryptodome==3.20.0
py-cpuinfo==9.0.0
psutil==5.9.8
prometheus-client==0.20.0
ipfshttpclient==0.8.0a2
structlog==24.2.0
pytest==8.2.2
pytest-asyncio==0.23.7
```

### 3.2 Node.js Frontend + Smart Contracts
```bash
# Install root dependencies (Hardhat + scripts)
npm install

# Install frontend dependencies
cd frontend && npm install && cd ..
```

**Root package.json dependencies:**
```json
{
  "dependencies": {
    "hardhat": "^2.22.3",
    "@openzeppelin/contracts": "^5.0.2",
    "@nomicfoundation/hardhat-toolbox": "^5.0.0",
    "viem": "^2.13.0",
    "dotenv": "^16.4.5"
  }
}
```

**frontend/package.json dependencies:**
```json
{
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "viem": "^2.13.0",
    "wagmi": "^2.9.4",
    "@tanstack/react-query": "^5.40.0",
    "lucide-react": "^0.383.0",
    "recharts": "^2.12.7",
    "tailwindcss": "^3.4.4",
    "react-hot-toast": "^2.4.1",
    "zustand": "^4.5.2",
    "axios": "^1.7.2"
  }
}
```

### 3.3 Browser Extension
```bash
cd extension
npm install
npm run build
cd ..
```

---

## Step 4: Database Setup

### 4.1 Start PostgreSQL + Redis (Docker)
```bash
docker-compose up -d postgres redis
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: chainguard
      POSTGRES_PASSWORD: password
      POSTGRES_DB: chainguard
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - ./data/redis:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    environment:
      GF_SECURITY_ADMIN_PASSWORD: chainguard
    volumes:
      - ./config/grafana:/etc/grafana/provisioning
    ports:
      - "3001:3000"
    restart: unless-stopped
```

### 4.2 Run Database Migrations
```bash
source venv/bin/activate
alembic upgrade head
```

### 4.3 Seed Threat Database
```bash
python scripts/seed_threatdb.py
```

---

## Step 5: Smart Contract Deployment

### 5.1 Local Development (Hardhat)
```bash
# Start local blockchain
npx hardhat node &

# Deploy contracts
npx hardhat run scripts/deploy.js --network localhost

# Run contract tests
npx hardhat test
```

### 5.2 Testnet Deployment (Sepolia)
```bash
# Ensure SEPOLIA_RPC and DEPLOYER_PRIVATE_KEY set in .env
npx hardhat run scripts/deploy.js --network sepolia

# Verify on Etherscan
npx hardhat verify --network sepolia <CONTRACT_ADDRESS> [constructor-args]
```

---

## Step 6: Start Backend Services

### 6.1 Start Sentinel Backend
```bash
source venv/bin/activate
cd backend
uvicorn sentinel:app --reload --host 0.0.0.0 --port 8000
```

### 6.2 Start Agent Network
```bash
# In separate terminal
source venv/bin/activate
python scripts/setup_agents.py

# This starts all 8 agents:
# [1/8] Starting OrchestratorAgent...       ✅
# [2/8] Starting PayloadScannerAgent...     ✅
# [3/8] Starting WalletSentinelAgent...     ✅
# [4/8] Starting ThreatIntelAgent...        ✅
# [5/8] Starting ContractAuditorAgent...    ✅
# [6/8] Starting IncidentResponderAgent...  ✅
# [7/8] Starting ReputationOracleAgent...   ✅
# [8/8] Starting NetworkGuardAgent...       ✅
# All agents ACTIVE. ChainGuard backend ready.
```

### 6.3 Verify All Services Running
```bash
python scripts/health_check.py

# Expected output:
# ┌──────────────────────────────────────────┐
# │  ChainGuard Health Check                 │
# │  Time: 2025-01-15 14:32:07 UTC          │
# ├──────────────────────────────────────────┤
# │  PostgreSQL          ✅ Connected        │
# │  Redis               ✅ Connected        │
# │  Sentinel API        ✅ Running :8000    │
# │  OrchestratorAgent   ✅ Active          │
# │  PayloadScannerAgent ✅ Active          │
# │  WalletSentinelAgent ✅ Active          │
# │  ThreatIntelAgent    ✅ Active          │
# │  ContractAuditorAgent✅ Active          │
# │  IncidentResponder   ✅ Active          │
# │  ReputationOracle    ✅ Active          │
# │  NetworkGuardAgent   ✅ Active          │
# │  ThreatRegistry.sol  ✅ Reachable       │
# │  ThreatFeed Sync     ✅ 4 min ago       │
# └──────────────────────────────────────────┘
# 
# STATUS: ALL SYSTEMS OPERATIONAL ✅
```

---

## Step 7: Start Frontend Dashboard

```bash
cd frontend
npm run dev

# Dashboard available at: http://localhost:3000
```

---

## Step 8: Install Browser Extension

### Chrome / Brave / Edge
1. Navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load Unpacked**
4. Select the `extension/dist/` directory
5. ChainGuard icon appears in toolbar

### Firefox
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `extension/dist/manifest.json`

### Verify Extension
1. Click ChainGuard icon in toolbar
2. Click **Connect to Sentinel** (enter `http://localhost:8000`)
3. Click **ACTIVATE PROTECTION**
4. Status should show: `🛡️ FULLY PROTECTED`

---

## Step 9: Run Full System Test

```bash
# Run integration test suite
python tests/test_full_pipeline.py

# Expected: All 47 tests pass
# Tests cover:
# - Extension RPC interception
# - Payload scanning accuracy (20 test vectors)
# - Wallet protection (10 drainer scenarios)
# - Agent communication (message bus)
# - Smart contract interactions
# - Incident response workflow
# - On-chain submission
```

---

## Production Deployment (Docker)

```bash
# Build all containers
docker-compose -f docker-compose.prod.yml build

# Start full stack
docker-compose -f docker-compose.prod.yml up -d

# Check all containers healthy
docker-compose -f docker-compose.prod.yml ps
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Agent not starting | Check Redis connection: `redis-cli ping` |
| RPC calls not intercepted | Reload extension, check CORS origins in .env |
| Contract calls failing | Verify contract addresses in .env match deployed |
| High CPU from agents | Reduce poll intervals in `config/agents.yaml` |
| False positives too high | Adjust `MAX_RISK_SCORE_BEFORE_BLOCK` in .env (increase slightly) |
| IPFS upload failing | Check IPFS credentials or use local IPFS node |

---

## Security Hardening (Production)

```bash
# Generate production secrets
python scripts/generate_secrets.py

# Enable TLS for Sentinel API
# Use nginx reverse proxy (config in config/nginx.conf)

# Rotate agent keys
python scripts/rotate_agent_keys.py

# Enable audit logging
export AUDIT_LOG_ENABLED=true

# Set up automated backups
crontab -e
# Add: 0 2 * * * /home/chainguard/scripts/backup.sh
```
