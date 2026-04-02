# 🖥️ ChainGuard Protocol — Frontend Specification

## Technology Stack
- **React 18** with hooks
- **Viem + Wagmi** for Web3 interactions
- **TailwindCSS** for styling
- **Recharts** for threat visualization
- **Zustand** for state management
- **React Hot Toast** for notifications

---

## Component Architecture

```
frontend/src/
├── App.jsx                    ← Root + routing
├── main.jsx                   ← Entry point with providers
├── components/
│   ├── layout/
│   │   ├── Navbar.jsx         ← Top navigation + wallet connect
│   │   └── Sidebar.jsx        ← Navigation sidebar
│   ├── dashboard/
│   │   ├── ProtectButton.jsx  ← ONE-CLICK main button
│   │   ├── ThreatMeter.jsx    ← Real-time threat level display
│   │   ├── AgentStatusGrid.jsx← 8 agent status cards
│   │   ├── LiveTxFeed.jsx     ← Streaming transaction analysis
│   │   └── StatsBar.jsx       ← Session statistics
│   ├── threats/
│   │   ├── ThreatFeed.jsx     ← Live intelligence feed
│   │   ├── BlockedTxList.jsx  ← Blocked transactions history
│   │   └── SubmitThreat.jsx   ← Report new threat form
│   ├── wallet/
│   │   ├── WalletStatus.jsx   ← MetaMask/Phantom status
│   │   ├── ApprovalsManager.jsx← Token approval revocation
│   │   └── IsolationToggle.jsx← Wallet isolation mode
│   └── shared/
│       ├── RiskBadge.jsx      ← Color-coded risk score
│       ├── AgentCard.jsx      ← Individual agent status
│       └── ThreatModal.jsx    ← Threat detail popup
├── hooks/
│   ├── useAgents.js           ← Agent status + communication
│   ├── useThreatFeed.js       ← WebSocket threat stream
│   ├── useWalletGuard.js      ← Wallet monitoring
│   └── useSentinel.js         ← Backend API calls
├── stores/
│   ├── protectionStore.js     ← Main protection state
│   ├── threatStore.js         ← Threat history
│   └── agentStore.js          ← Agent status
└── utils/
    ├── riskColors.js          ← Risk level color mapping
    ├── threatFormatters.js    ← Format threat data for display
    └── api.js                 ← Axios instance + interceptors
```

---

## Key Component: ProtectButton.jsx

```jsx
// The ONE-CLICK solution button
import { useState, useEffect } from "react";
import { Shield, ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";
import { useProtectionStore } from "../stores/protectionStore";

export default function ProtectButton() {
  const { 
    status,          // "IDLE" | "ACTIVATING" | "ACTIVE" | "THREAT_DETECTED"
    activateAll,     // Function to start all agents
    deactivateAll,   // Function to stop all agents
    sessionStats,    // { threats_blocked, txs_analyzed, time_active }
    currentThreat    // Active threat data if any
  } = useProtectionStore();

  const buttonConfig = {
    IDLE: {
      text: "ACTIVATE PROTECTION",
      icon: <Shield className="w-8 h-8" />,
      style: "bg-blue-600 hover:bg-blue-700 text-white",
      pulse: false
    },
    ACTIVATING: {
      text: "INITIALIZING...",
      icon: <Loader2 className="w-8 h-8 animate-spin" />,
      style: "bg-yellow-500 text-white cursor-wait",
      pulse: false
    },
    ACTIVE: {
      text: "PROTECTED",
      icon: <ShieldCheck className="w-8 h-8" />,
      style: "bg-emerald-600 hover:bg-emerald-700 text-white",
      pulse: true
    },
    THREAT_DETECTED: {
      text: "THREAT BLOCKED",
      icon: <ShieldAlert className="w-8 h-8" />,
      style: "bg-red-600 hover:bg-red-700 text-white",
      pulse: true
    }
  };

  const config = buttonConfig[status];

  return (
    <div className="flex flex-col items-center gap-6">
      {/* Main Button */}
      <button
        onClick={status === "IDLE" ? activateAll : deactivateAll}
        disabled={status === "ACTIVATING"}
        className={`
          relative w-48 h-48 rounded-full font-bold text-lg
          flex flex-col items-center justify-center gap-2
          transition-all duration-300 shadow-2xl
          ${config.style}
          ${config.pulse ? "animate-pulse" : ""}
        `}
      >
        {/* Outer ring animation */}
        {status === "ACTIVE" && (
          <div className="absolute inset-0 rounded-full border-4 border-emerald-400 
                          animate-ping opacity-20" />
        )}
        {status === "THREAT_DETECTED" && (
          <div className="absolute inset-0 rounded-full border-4 border-red-400 
                          animate-ping" />
        )}
        
        {config.icon}
        <span className="text-sm font-bold tracking-wider">{config.text}</span>
      </button>

      {/* Session Stats (when active) */}
      {(status === "ACTIVE" || status === "THREAT_DETECTED") && (
        <div className="grid grid-cols-3 gap-4 text-center">
          <StatPill
            label="Threats Blocked"
            value={sessionStats.threats_blocked}
            color="red"
          />
          <StatPill
            label="TXs Analyzed"
            value={sessionStats.txs_analyzed.toLocaleString()}
            color="blue"
          />
          <StatPill
            label="Protected For"
            value={formatDuration(sessionStats.time_active)}
            color="emerald"
          />
        </div>
      )}

      {/* Threat Alert Banner */}
      {status === "THREAT_DETECTED" && currentThreat && (
        <div className="bg-red-950 border border-red-500 rounded-xl p-4 
                        max-w-md text-sm text-red-200">
          <div className="font-bold text-red-400 mb-1">
            🚨 {currentThreat.headline}
          </div>
          <div>{currentThreat.summary}</div>
          <button className="mt-2 text-xs text-red-400 underline">
            View Full Incident Report →
          </button>
        </div>
      )}
    </div>
  );
}
```

---

## Key Component: AgentStatusGrid.jsx

```jsx
// Displays all 8 agents with real-time health indicators
const AGENTS = [
  { id: "orchestrator", name: "Orchestrator", icon: "🎯", desc: "Master Coordinator" },
  { id: "payload_scanner", name: "Payload Scanner", icon: "🔬", desc: "Malware Detector" },
  { id: "wallet_sentinel", name: "Wallet Sentinel", icon: "👛", desc: "Wallet Guardian" },
  { id: "threat_intel", name: "Threat Intel", icon: "🕵️", desc: "Intelligence Feeds" },
  { id: "contract_auditor", name: "Contract Auditor", icon: "📋", desc: "Pre-exec Simulator" },
  { id: "incident_responder", name: "Incident Responder", icon: "🚒", desc: "Auto Response" },
  { id: "reputation_oracle", name: "Reputation Oracle", icon: "⭐", desc: "Address Scorer" },
  { id: "network_guard", name: "Network Guard", icon: "🌐", desc: "Process Monitor" }
];

export default function AgentStatusGrid({ agentStatuses }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {AGENTS.map(agent => {
        const status = agentStatuses[agent.id] || "OFFLINE";
        return (
          <div
            key={agent.id}
            className={`
              rounded-xl p-3 border
              ${status === "ACTIVE" 
                ? "bg-emerald-950 border-emerald-700" 
                : status === "DEGRADED"
                  ? "bg-yellow-950 border-yellow-700"
                  : "bg-slate-900 border-slate-700"}
            `}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xl">{agent.icon}</span>
              <div className={`w-2 h-2 rounded-full ${
                status === "ACTIVE" ? "bg-emerald-400 animate-pulse" :
                status === "DEGRADED" ? "bg-yellow-400" : "bg-slate-600"
              }`} />
            </div>
            <div className="text-xs font-semibold text-white">{agent.name}</div>
            <div className="text-xs text-slate-400">{agent.desc}</div>
            <div className={`text-xs mt-1 font-mono ${
              status === "ACTIVE" ? "text-emerald-400" :
              status === "DEGRADED" ? "text-yellow-400" : "text-slate-500"
            }`}>{status}</div>
          </div>
        );
      })}
    </div>
  );
}
```

---

## Key Component: LiveTxFeed.jsx

```jsx
// Real-time transaction analysis stream
export default function LiveTxFeed({ transactions }) {
  return (
    <div className="bg-slate-900 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
        <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
        <span className="text-sm font-semibold text-white">Live Transaction Feed</span>
      </div>
      
      <div className="overflow-y-auto max-h-96">
        {transactions.map(tx => (
          <div
            key={tx.hash}
            className={`
              px-4 py-3 border-b border-slate-800 flex items-center gap-3
              ${tx.verdict === "BLOCK" ? "bg-red-950/30" : 
                tx.verdict === "WARN" ? "bg-yellow-950/30" : ""}
            `}
          >
            {/* Verdict Icon */}
            <div className={`text-lg ${
              tx.verdict === "BLOCK" ? "text-red-400" :
              tx.verdict === "WARN" ? "text-yellow-400" : "text-emerald-400"
            }`}>
              {tx.verdict === "BLOCK" ? "🛑" : 
               tx.verdict === "WARN" ? "⚠️" : "✅"}
            </div>
            
            {/* TX Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-300">
                  {tx.hash.slice(0, 10)}...{tx.hash.slice(-6)}
                </span>
                <RiskBadge score={tx.risk_score} />
              </div>
              <div className="text-xs text-slate-500 truncate">
                {tx.description || `${tx.method} → ${tx.to?.slice(0, 8)}...`}
              </div>
            </div>
            
            {/* Risk Score */}
            <div className={`text-sm font-bold ${
              tx.risk_score >= 70 ? "text-red-400" :
              tx.risk_score >= 40 ? "text-yellow-400" : "text-emerald-400"
            }`}>
              {tx.risk_score}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

## Main Dashboard Layout

```jsx
// App.jsx — Main dashboard
export default function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar />
      
      <main className="container mx-auto px-4 py-8 max-w-7xl">
        
        {/* Hero: One-Click Protection */}
        <section className="flex flex-col items-center py-12 gap-8">
          <h1 className="text-4xl font-black tracking-tight">
            ⛓️🛡️ <span className="text-blue-400">ChainGuard</span> Protocol
          </h1>
          <p className="text-slate-400 text-center max-w-md">
            One-click blockchain malware defense. 
            Powered by 8 AI agents and decentralized threat intelligence.
          </p>
          <ProtectButton />
        </section>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Left: Agent Status */}
          <div className="lg:col-span-2 space-y-6">
            <AgentStatusGrid agentStatuses={agentStatuses} />
            <LiveTxFeed transactions={recentTxs} />
          </div>
          
          {/* Right: Threat Intelligence */}
          <div className="space-y-6">
            <ThreatMeter level={threatLevel} />
            <ThreatFeed threats={recentThreats} />
          </div>
        </div>
        
      </main>
    </div>
  );
}
```

---

## Color System

```javascript
// utils/riskColors.js
export const getRiskColor = (score) => {
  if (score >= 90) return { bg: "bg-red-600", text: "text-red-400", label: "CRITICAL" };
  if (score >= 70) return { bg: "bg-orange-600", text: "text-orange-400", label: "HIGH" };
  if (score >= 40) return { bg: "bg-yellow-600", text: "text-yellow-400", label: "MEDIUM" };
  if (score >= 20) return { bg: "bg-blue-600", text: "text-blue-400", label: "LOW" };
  return { bg: "bg-emerald-600", text: "text-emerald-400", label: "SAFE" };
};
```
