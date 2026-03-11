import { useState, useEffect, useRef, useCallback } from "react";

//Data

const PQC_ALGORITHMS = {
  "CRYSTALS-Dilithium2": {
    type: "Signature", nistLevel: 2,
    pubKeyBytes: 1312, privKeyBytes: 2528, sigBytes: 2420,
    keygen_ms: 0.087, sign_ms: 0.18, verify_ms: 0.13,
    quantumSafe: true, classical: false,
    basis: "Lattice (Module-LWE)",
    color: "#6ee7f7",
    strengths: ["NIST Standard", "Fast keygen", "Moderate size"],
    weaknesses: ["Large signatures vs ECDSA", "New implementation risks"],
  },
  "CRYSTALS-Dilithium3": {
    type: "Signature", nistLevel: 3,
    pubKeyBytes: 1952, privKeyBytes: 4000, sigBytes: 3293,
    keygen_ms: 0.13, sign_ms: 0.27, verify_ms: 0.18,
    quantumSafe: true, classical: false,
    basis: "Lattice (Module-LWE)",
    color: "#4f9cf7",
    strengths: ["Higher security margin", "NIST Standard"],
    weaknesses: ["Larger footprint", "Slower than Dilithium2"],
  },
  "FALCON-512": {
    type: "Signature", nistLevel: 1,
    pubKeyBytes: 897, privKeyBytes: 1281, sigBytes: 666,
    keygen_ms: 8.4, sign_ms: 0.44, verify_ms: 0.09,
    quantumSafe: true, classical: false,
    basis: "Lattice (NTRU)",
    color: "#a78bfa",
    strengths: ["Smallest PQC signatures", "Fast verify"],
    weaknesses: ["Slow keygen", "Complex implementation", "Timing attacks risk"],
  },
  "FALCON-1024": {
    type: "Signature", nistLevel: 5,
    pubKeyBytes: 1793, privKeyBytes: 2305, sigBytes: 1280,
    keygen_ms: 17.1, sign_ms: 0.85, verify_ms: 0.17,
    quantumSafe: true, classical: false,
    basis: "Lattice (NTRU)",
    color: "#c084fc",
    strengths: ["Highest PQC security", "Compact signatures"],
    weaknesses: ["Very slow keygen", "Resource intensive"],
  },
  "SPHINCS+-128s": {
    type: "Signature", nistLevel: 1,
    pubKeyBytes: 32, privKeyBytes: 64, sigBytes: 7856,
    keygen_ms: 1.68, sign_ms: 1260, verify_ms: 2.34,
    quantumSafe: true, classical: false,
    basis: "Hash-based (Stateless)",
    color: "#34d399",
    strengths: ["Conservative security", "Small keys", "No algebraic assumptions"],
    weaknesses: ["Enormous signatures", "Very slow signing"],
  },
  "CRYSTALS-Kyber512": {
    type: "KEM", nistLevel: 1,
    pubKeyBytes: 800, privKeyBytes: 1632, sigBytes: 768,
    keygen_ms: 0.057, sign_ms: 0.063, verify_ms: 0.051,
    quantumSafe: true, classical: false,
    basis: "Lattice (Module-LWE)",
    color: "#fbbf24",
    strengths: ["Fast KEM", "NIST Standard", "Compact"],
    weaknesses: ["KEM only (not signature)", "Newer than RSA"],
  },
  "ECDSA-P256 (Classical)": {
    type: "Signature", nistLevel: 0,
    pubKeyBytes: 64, privKeyBytes: 32, sigBytes: 64,
    keygen_ms: 0.029, sign_ms: 0.044, verify_ms: 0.065,
    quantumSafe: false, classical: true,
    basis: "Elliptic Curve (ECDLP)",
    color: "#f87171",
    strengths: ["Tiny keys", "Very fast", "Battle-tested", "Universal support"],
    weaknesses: ["Broken by Shor's algorithm", "Quantum vulnerable"],
  },
  "RSA-2048 (Classical)": {
    type: "Signature", nistLevel: 0,
    pubKeyBytes: 256, privKeyBytes: 256, sigBytes: 256,
    keygen_ms: 56.3, sign_ms: 0.74, verify_ms: 0.028,
    quantumSafe: false, classical: true,
    basis: "Integer Factorization",
    color: "#fb923c",
    strengths: ["Wide compatibility", "Fast verify"],
    weaknesses: ["Broken by Shor's algorithm", "Slow keygen"],
  },
};

const MIGRATION_STRATEGIES = {
  "Hard Fork Migration": {
    securityScore: 95, performanceScore: 55, compatibilityScore: 20,
    description: "Complete replacement of ECDSA with PQC in a single hard fork. All nodes must upgrade simultaneously.",
    phases: ["Block height X: halt", "Full protocol swap", "PQC-only resume"],
    risk: "High",
    timeEstimate: "6-12 months",
    color: "#ef4444",
  },
  "Soft Fork Hybrid": {
    securityScore: 80, performanceScore: 65, compatibilityScore: 75,
    description: "PQC signatures added alongside classical, old nodes see valid txns. Gradual quantum-proofing.",
    phases: ["Enable dual-signature", "Incentivize PQC adoption", "Sunset classical"],
    risk: "Medium",
    timeEstimate: "12-24 months",
    color: "#f59e0b",
  },
  "Layered Address Migration": {
    securityScore: 85, performanceScore: 72, compatibilityScore: 82,
    description: "New PQC address format introduced, old UTXOs migrated via claim mechanism.",
    phases: ["PQC address type", "Migration window", "Classical freeze"],
    risk: "Medium-Low",
    timeEstimate: "18-36 months",
    color: "#3b82f6",
  },
  "AQMP Framework (Proposed)": {
    securityScore: 93, performanceScore: 87, compatibilityScore: 91,
    description: "Adaptive Quantum Migration Protocol — temporal decoupling of security/performance/compatibility upgrades using ZK-aggregated PQC proofs and recursive commitment schemes.",
    phases: ["Dual-commit layer", "ZK-aggregate proofs", "Adaptive param selection", "Full PQC finality"],
    risk: "Low",
    timeEstimate: "24-48 months",
    color: "#10b981",
    isProposed: true,
  },
};

//Trilemma Triangle SVG
function TrilemmaTriangle({ scores, strategy }) {
  const cx = 200, cy = 195, R = 140;
  //Vertices: Security (top), Performance (bottom-left), Compatibility (bottom-right)
  const vertices = [
    { x: cx, y: cy - R, label: "Security", key: "securityScore" },
    { x: cx - R * 0.866, y: cy + R * 0.5, label: "Performance", key: "performanceScore" },
    { x: cx + R * 0.866, y: cy + R * 0.5, label: "Compatibility", key: "compatibilityScore" },
  ];

  const getPoint = (vertex, score) => {
    const ratio = (score / 100) * 0.85 + 0.0;
    return {
      x: cx + (vertex.x - cx) * ratio,
      y: cy + (vertex.y - cy) * ratio,
    };
  };

  const points = vertices.map(v => getPoint(v, scores[v.key]));
  const polyStr = points.map(p => `${p.x},${p.y}`).join(" ");

  const gridLevels = [0.25, 0.5, 0.75, 1.0];

  return (
    <svg viewBox="0 0 400 400" style={{ width: "100%", maxWidth: 420 }}>
      <defs>
        <radialGradient id="bgGrad" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#0f1729" />
          <stop offset="100%" stopColor="#060d1a" />
        </radialGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur" />
          <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <linearGradient id="fillGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={strategy.color} stopOpacity="0.5" />
          <stop offset="100%" stopColor={strategy.color} stopOpacity="0.2" />
        </linearGradient>
      </defs>
      <rect width="400" height="400" fill="url(#bgGrad)" rx="12" />

      {gridLevels.map((level, i) => {
        const gpts = vertices.map(v => ({
          x: cx + (v.x - cx) * level,
          y: cy + (v.y - cy) * level,
        }));
        return (
          <polygon key={i}
            points={gpts.map(p => `${p.x},${p.y}`).join(" ")}
            fill="none" stroke="#1e3a5f" strokeWidth={i === 3 ? 1 : 0.5}
            strokeDasharray={i < 3 ? "4,4" : "none"} />
        );
      })}

      {vertices.map((v, i) => (
        <line key={i} x1={cx} y1={cy} x2={v.x} y2={v.y}
          stroke="#1e3a5f" strokeWidth="1" />
      ))}

      <polygon points={polyStr}
        fill="url(#fillGrad)" stroke={strategy.color}
        strokeWidth="2.5" filter="url(#glow)" />

      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r="5"
          fill={strategy.color} filter="url(#glow)" />
      ))}

      {vertices.map((v, i) => {
        const offset = { x: 0, y: 0 };
        if (i === 0) { offset.y = -18; }
        if (i === 1) { offset.x = -18; offset.y = 14; }
        if (i === 2) { offset.x = 18; offset.y = 14; }
        return (
          <g key={i}>
            <text x={v.x + offset.x} y={v.y + offset.y}
              textAnchor="middle" fill="#94a3b8"
              fontSize="11" fontFamily="monospace" fontWeight="bold">
              {v.label}
            </text>
            <text x={v.x + offset.x} y={v.y + offset.y + 14}
              textAnchor="middle" fill={strategy.color}
              fontSize="13" fontFamily="monospace" fontWeight="bold">
              {scores[v.key]}%
            </text>
          </g>
        );
      })}

      {/* Center label */}
      <text x={cx} y={cy - 8} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
        TRILEMMA
      </text>
      <text x={cx} y={cy + 6} textAnchor="middle" fill={strategy.color} fontSize="10" fontFamily="monospace" fontWeight="bold">
        {strategy.isProposed ? "AQMP" : "SCORE"}
      </text>
      {strategy.isProposed && (
        <text x={cx} y={cy + 20} textAnchor="middle" fill="#10b981" fontSize="8" fontFamily="monospace">
          TRILEMMA BROKEN
        </text>
      )}
    </svg>
  );
}

//Algorithm Bar Chart
function AlgoBar({ label, value, max, color, unit }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
        <span style={{ color: "#94a3b8", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
        <span style={{ color, fontSize: 11, fontFamily: "monospace", fontWeight: "bold" }}>
          {value} {unit}
        </span>
      </div>
      <div style={{ height: 6, background: "#0f172a", borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${pct}%`, background: color,
          borderRadius: 3, transition: "width 0.5s ease",
          boxShadow: `0 0 6px ${color}80`,
        }} />
      </div>
    </div>
  );
}

//Main App
export default function PQCTrilemmaResearch() {
  const [activeTab, setActiveTab] = useState("trilemma");
  const [selectedStrategy, setSelectedStrategy] = useState("AQMP Framework (Proposed)");
  const [selectedAlgos, setSelectedAlgos] = useState(["CRYSTALS-Dilithium2", "FALCON-512", "ECDSA-P256 (Classical)"]);
  const [algoMetric, setAlgoMetric] = useState("sigBytes");
  const [simStep, setSimStep] = useState(0);
  const [simRunning, setSimRunning] = useState(false);
  const [quantumYear, setQuantumYear] = useState(2035);
  const [txVolume, setTxVolume] = useState(7);
  const simRef = useRef(null);

  const strategy = MIGRATION_STRATEGIES[selectedStrategy];

  //Simulation
  const startSim = useCallback(() => {
    setSimStep(0);
    setSimRunning(true);
  }, []);

  useEffect(() => {
    if (simRunning) {
      const phases = strategy.phases;
      simRef.current = setInterval(() => {
        setSimStep(prev => {
          if (prev >= phases.length - 1) {
            clearInterval(simRef.current);
            setSimRunning(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1200);
    }
    return () => clearInterval(simRef.current);
  }, [simRunning, strategy]);

  const toggleAlgo = (name) => {
    setSelectedAlgos(prev =>
      prev.includes(name)
        ? prev.filter(a => a !== name)
        : [...prev, name]
    );
  };

  //Compute urgency score
  const yearsLeft = quantumYear - 2025;
  const urgency = Math.max(0, Math.min(100, 100 - yearsLeft * 5));

  const metricLabels = {
    sigBytes: { label: "Signature Size", unit: "bytes", max: 8000 },
    pubKeyBytes: { label: "Public Key Size", unit: "bytes", max: 2000 },
    sign_ms: { label: "Sign Time", unit: "ms", max: 1300 },
    verify_ms: { label: "Verify Time", unit: "ms", max: 3 },
    keygen_ms: { label: "Keygen Time", unit: "ms", max: 60 },
  };

  const tabs = [
    { id: "trilemma", label: "Trilemma" },
    { id: "algorithms", label: "Algorithms" },
    { id: "simulator", label: "Simulator" },
    { id: "aqmp", label: "AQMP" },
    { id: "threat", label: "Threat" },
  ];

  //Styles
  const S = {
    root: {
      minHeight: "100vh", background: "#040b18",
      color: "#e2e8f0", fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
      padding: "0",
    },
    header: {
      background: "linear-gradient(135deg, #0a1628 0%, #0d1f3c 50%, #071321 100%)",
      borderBottom: "1px solid #1e3a5f",
      padding: "20px 28px 16px",
    },
    title: {
      fontSize: 22, fontWeight: "bold", color: "#e2e8f0",
      letterSpacing: "0.05em", margin: 0,
      textShadow: "0 0 20px #3b82f640",
    },
    subtitle: {
      fontSize: 11, color: "#4a7fa5", marginTop: 4,
      letterSpacing: "0.1em", textTransform: "uppercase",
    },
    badge: (color) => ({
      display: "inline-block", padding: "2px 8px",
      background: `${color}22`, border: `1px solid ${color}55`,
      color, borderRadius: 3, fontSize: 10, marginLeft: 10,
      letterSpacing: "0.08em",
    }),
    nav: {
      display: "flex", gap: 2, padding: "10px 28px 0",
      background: "#040b18", borderBottom: "1px solid #0f2040",
      overflowX: "auto",
    },
    tabBtn: (active) => ({
      padding: "8px 16px", cursor: "pointer", border: "none",
      background: active ? "#0d1f3c" : "transparent",
      color: active ? "#6ee7f7" : "#4a7fa5",
      borderBottom: active ? "2px solid #6ee7f7" : "2px solid transparent",
      fontSize: 11, fontFamily: "monospace", letterSpacing: "0.05em",
      fontWeight: active ? "bold" : "normal",
      transition: "all 0.2s", whiteSpace: "nowrap",
    }),
    content: { padding: "24px 28px", maxWidth: 1100 },
    card: {
      background: "#080f1e", border: "1px solid #0f2040",
      borderRadius: 8, padding: 20, marginBottom: 16,
    },
    cardTitle: {
      fontSize: 12, color: "#4a7fa5", textTransform: "uppercase",
      letterSpacing: "0.1em", marginBottom: 12, fontWeight: "bold",
    },
    grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 },
    grid3: { display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 },
    stratBtn: (name, sel) => ({
      padding: "10px 14px", cursor: "pointer", borderRadius: 6,
      border: `1px solid ${sel === name ? MIGRATION_STRATEGIES[name].color : "#1e3a5f"}`,
      background: sel === name ? `${MIGRATION_STRATEGIES[name].color}15` : "#0a1424",
      color: sel === name ? MIGRATION_STRATEGIES[name].color : "#64748b",
      fontSize: 10, fontFamily: "monospace", textAlign: "left",
      transition: "all 0.2s", width: "100%", marginBottom: 6,
      boxShadow: sel === name ? `0 0 12px ${MIGRATION_STRATEGIES[name].color}30` : "none",
    }),
    algoChip: (name, sel) => ({
      padding: "5px 10px", cursor: "pointer", borderRadius: 4,
      border: `1px solid ${sel.includes(name) ? PQC_ALGORITHMS[name].color : "#1e3a5f"}`,
      background: sel.includes(name) ? `${PQC_ALGORITHMS[name].color}15` : "#0a1424",
      color: sel.includes(name) ? PQC_ALGORITHMS[name].color : "#64748b",
      fontSize: 10, fontFamily: "monospace",
      display: "inline-block", margin: "3px",
      transition: "all 0.15s",
    }),
    scoreRing: (score, color) => ({
      width: 72, height: 72, borderRadius: "50%",
      background: `conic-gradient(${color} ${score * 3.6}deg, #0f172a 0)`,
      display: "flex", alignItems: "center", justifyContent: "center",
      position: "relative",
    }),
    innerRing: {
      width: 52, height: 52, borderRadius: "50%",
      background: "#080f1e", display: "flex",
      alignItems: "center", justifyContent: "center",
      flexDirection: "column",
    },
  };

  //THREAT MODEL TAB
  const renderThreat = () => (
    <div>
      <div style={S.card}>
        <div style={S.cardTitle}>Quantum Threat Timeline Estimator</div>
        <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 20, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <div style={{ color: "#94a3b8", fontSize: 11, marginBottom: 6 }}>
              Estimated CRQC Year: <span style={{ color: "#fbbf24", fontWeight: "bold" }}>{quantumYear}</span>
            </div>
            <input type="range" min="2028" max="2045" value={quantumYear}
              onChange={e => setQuantumYear(+e.target.value)}
              style={{ width: "100%", accentColor: "#fbbf24" }} />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#4a7fa5" }}>
              <span>2028 (Optimistic)</span><span>2045 (Conservative)</span>
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 220 }}>
            <div style={{ color: "#94a3b8", fontSize: 11, marginBottom: 6 }}>
              Blockchain TPS: <span style={{ color: "#6ee7f7", fontWeight: "bold" }}>{txVolume * 1000} tx/s</span>
            </div>
            <input type="range" min="1" max="50" value={txVolume}
              onChange={e => setTxVolume(+e.target.value)}
              style={{ width: "100%", accentColor: "#6ee7f7" }} />
          </div>
        </div>

        <div style={S.grid3}>
          {[
            { label: "Quantum Urgency", value: urgency, color: urgency > 70 ? "#ef4444" : urgency > 40 ? "#fbbf24" : "#22c55e", suffix: "%" },
            { label: "Years to Migrate", value: Math.max(1, yearsLeft - 5), color: "#6ee7f7", suffix: "yrs" },
            { label: "HARVEST NOW Risk", value: Math.min(100, (2025 - 2015) * 8 + (quantumYear < 2032 ? 40 : 20)), color: "#f87171", suffix: "%" },
          ].map((item, i) => (
            <div key={i} style={{ ...S.card, textAlign: "center", marginBottom: 0 }}>
              <div style={S.cardTitle}>{item.label}</div>
              <div style={{ fontSize: 32, fontWeight: "bold", color: item.color }}>
                {item.value}{item.suffix}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Attack Vectors on Current Blockchain Cryptography</div>
        {[
          { attack: "Shor's Algorithm → ECDSA/RSA Break", target: "Key derivation & signatures", impact: 100, color: "#ef4444" },
          { attack: "Grover's Algorithm → SHA-256 Weakening", target: "PoW mining, hash functions", impact: 50, color: "#fbbf24" },
          { attack: "Harvest-Now-Decrypt-Later (HNDL)", target: "Encrypted tx metadata", impact: 85, color: "#f97316" },
          { attack: "Quantum Replay Attack", target: "Exposed public keys", impact: 90, color: "#ef4444" },
          { attack: "Quantum Oracle Attack → ZK proofs", target: "SNARK/STARK circuits", impact: 60, color: "#a78bfa" },
        ].map((a, i) => (
          <div key={i} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ color: "#e2e8f0", fontSize: 12 }}>{a.attack}</span>
              <span style={{ color: a.color, fontSize: 11, fontWeight: "bold" }}>Impact: {a.impact}%</span>
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginBottom: 4 }}>Target: {a.target}</div>
            <div style={{ height: 5, background: "#0f172a", borderRadius: 3 }}>
              <div style={{ height: "100%", width: `${a.impact}%`, background: a.color, borderRadius: 3, boxShadow: `0 0 8px ${a.color}60` }} />
            </div>
          </div>
        ))}
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Blockchain Assets at Risk (HNDL exposure)</div>
        <div style={S.grid2}>
          {[
            { asset: "Bitcoin (BTC)", exposed: "~4M BTC in reused addresses", risk: "HIGH", color: "#f97316" },
            { asset: "Ethereum (ETH)", exposed: "EOA wallets with public keys", risk: "CRITICAL", color: "#ef4444" },
            { asset: "DeFi Smart Contracts", exposed: "On-chain signature verification", risk: "HIGH", color: "#f97316" },
            { asset: "Lightning Network", exposed: "Channel funding keys", risk: "MEDIUM", color: "#fbbf24" },
          ].map((item, i) => (
            <div key={i} style={{ ...S.card, marginBottom: 0, border: `1px solid ${item.color}30` }}>
              <div style={{ color: "#e2e8f0", fontSize: 12, fontWeight: "bold", marginBottom: 6 }}>{item.asset}</div>
              <div style={{ color: "#94a3b8", fontSize: 10, marginBottom: 8 }}>{item.exposed}</div>
              <span style={{ ...S.badge(item.color), marginLeft: 0 }}>Risk: {item.risk}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  //AQMP TAB
  const renderAQMP = () => (
    <div>
      <div style={{ ...S.card, borderColor: "#10b98140" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div style={{ fontSize: 32 }}>✦</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: "bold", color: "#10b981" }}>
              Adaptive Quantum Migration Protocol (AQMP)
            </div>
            <div style={{ fontSize: 11, color: "#4a7fa5" }}>
              Proposed Framework — Breaking the PQC Blockchain Trilemma
            </div>
          </div>
        </div>
        <p style={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.7 }}>
          AQMP addresses the fundamental tension between Security, Performance, and Compatibility 
          by employing <span style={{ color: "#6ee7f7" }}>temporal decoupling</span> — separating 
          the upgrade timeline of each trilemma vertex into independent, asynchronous migration tracks 
          that converge via a <span style={{ color: "#10b981" }}>ZK-aggregated commitment layer</span>.
        </p>
      </div>

      <div style={S.grid2}>
        <div style={S.card}>
          <div style={S.cardTitle}>🔑 Core Mechanisms</div>
          {[
            { icon: "①", title: "Dual-Commit Layer (DCL)", desc: "Each transaction commits to both ECDSA and PQC (Dilithium/FALCON) simultaneously. Classical nodes verify ECDSA; quantum-safe nodes verify PQC. No fork required.", color: "#6ee7f7" },
            { icon: "②", title: "ZK-Aggregated PQC Proofs", desc: "Multiple FALCON-512 signatures (~666B each) are recursively folded into a single STARK proof (~1-2KB), achieving O(1) verification regardless of signature count.", color: "#a78bfa" },
            { icon: "③", title: "Adaptive Parameter Selection", desc: "Protocol dynamically selects PQC algorithm tier based on: tx value, UTXO age, threat level score, and available block space — optimizing each dimension independently.", color: "#fbbf24" },
            { icon: "④", title: "Quantum Threat Oracle (QTO)", desc: "Decentralized oracle network monitoring NIST PQC developments, quantum computing benchmarks, and activates emergency migration if CRQC threshold is detected.", color: "#10b981" },
          ].map((m, i) => (
            <div key={i} style={{ marginBottom: 14, paddingBottom: 14, borderBottom: i < 3 ? "1px solid #0f2040" : "none" }}>
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span style={{ color: m.color, fontSize: 16, fontWeight: "bold", minWidth: 20 }}>{m.icon}</span>
                <div>
                  <div style={{ color: m.color, fontSize: 12, fontWeight: "bold", marginBottom: 4 }}>{m.title}</div>
                  <div style={{ color: "#94a3b8", fontSize: 11, lineHeight: 1.6 }}>{m.desc}</div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div>
          <div style={S.card}>
            <div style={S.cardTitle}>Why AQMP Breaks the Trilemma</div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
                <thead>
                  <tr>
                    {["Constraint", "Problem", "AQMP Solution"].map(h => (
                      <th key={h} style={{ padding: "8px", textAlign: "left", color: "#4a7fa5", borderBottom: "1px solid #1e3a5f", whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["Security", "PQC algo not universal", "ZK-folded proofs guarantee quantum resistance without exposing raw PQC sigs"],
                    ["Performance", "PQC sigs 10-40× larger", "Recursive aggregation keeps block overhead ~5-12% vs baseline"],
                    ["Compatibility", "Existing nodes reject PQC", "DCL embeds PQC inside OP_RETURN / extra data field; old nodes see valid classical tx"],
                  ].map(([c, p, s], i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #0f2040" }}>
                      <td style={{ padding: "8px", color: "#6ee7f7", fontWeight: "bold" }}>{c}</td>
                      <td style={{ padding: "8px", color: "#94a3b8" }}>{p}</td>
                      <td style={{ padding: "8px", color: "#10b981" }}>{s}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div style={S.card}>
            <div style={S.cardTitle}>Performance Projection vs Baseline</div>
            {[
              { metric: "Block size overhead", baseline: "+1200%", aqmp: "+8%", better: true },
              { metric: "Signature verify time", baseline: "3.8×", aqmp: "1.1×", better: true },
              { metric: "Full node upgrade req", baseline: "100%", aqmp: "0% (gradual)", better: true },
              { metric: "Migration downtime", baseline: "24-72h", aqmp: "0 (seamless)", better: true },
              { metric: "Quantum security level", baseline: "0 (none)", aqmp: "NIST Level 2+", better: true },
            ].map((item, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid #0a1424", fontSize: 11 }}>
                <span style={{ color: "#94a3b8" }}>{item.metric}</span>
                <span style={{ color: "#ef4444", marginRight: 12 }}>{item.baseline}</span>
                <span style={{ color: "#10b981", fontWeight: "bold" }}>{item.aqmp}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>AQMP Architecture Layers</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {[
            { layer: "L4: Application Layer", desc: "Wallet UX, DApp integration, automatic PQC address generation", color: "#6ee7f7", width: "100%" },
            { layer: "L3: ZK Aggregation Layer", desc: "STARK/SNARK recursive proof folding of PQC signatures, Plonky2/Halo2 circuits", color: "#a78bfa", width: "85%" },
            { layer: "L2: Dual-Commit Protocol", desc: "Transaction structure: [Classical sig] + [PQC commitment] + [ZK-proof pointer]", color: "#fbbf24", width: "70%" },
            { layer: "L1: Consensus + Blockchain", desc: "Existing PoW/PoS/BFT unchanged — AQMP operates above consensus", color: "#10b981", width: "55%" },
            { layer: "L0: Quantum Threat Oracle", desc: "Off-chain monitoring, emergency migration triggers, NIST PQC tracking", color: "#f87171", width: "40%" },
          ].map((l, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ width: l.width, minWidth: 120, background: `${l.color}15`, border: `1px solid ${l.color}40`, borderRadius: 4, padding: "8px 12px" }}>
                <div style={{ color: l.color, fontSize: 11, fontWeight: "bold" }}>{l.layer}</div>
                <div style={{ color: "#64748b", fontSize: 10, marginTop: 2 }}>{l.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  //SIMULATOR TAB
  const renderSimulator = () => (
    <div>
      <div style={S.card}>
        <div style={S.cardTitle}>Migration Strategy Simulator</div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <div style={{ minWidth: 200 }}>
            {Object.keys(MIGRATION_STRATEGIES).map(name => (
              <button key={name} style={S.stratBtn(name, selectedStrategy)}
                onClick={() => { setSelectedStrategy(name); setSimStep(0); setSimRunning(false); }}>
                <div style={{ fontWeight: "bold", marginBottom: 2 }}>{name}</div>
                <div style={{ color: MIGRATION_STRATEGIES[name].color + "99", fontSize: 9 }}>
                  Risk: {MIGRATION_STRATEGIES[name].risk} · {MIGRATION_STRATEGIES[name].timeEstimate}
                </div>
              </button>
            ))}
          </div>

          <div style={{ flex: 1 }}>
            <TrilemmaTriangle
              scores={strategy}
              strategy={strategy}
            />
          </div>

          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ ...S.card, marginBottom: 12 }}>
              <div style={S.cardTitle}>SCORE BREAKDOWN</div>
              {[
                { key: "securityScore", label: "Security", color: "#6ee7f7" },
                { key: "performanceScore", label: "Performance", color: "#a78bfa" },
                { key: "compatibilityScore", label: "Compatibility", color: "#fbbf24" },
              ].map(dim => (
                <div key={dim.key} style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, fontSize: 11 }}>
                    <span style={{ color: "#94a3b8" }}>{dim.label}</span>
                    <span style={{ color: dim.color, fontWeight: "bold" }}>{strategy[dim.key]}%</span>
                  </div>
                  <div style={{ height: 8, background: "#0f172a", borderRadius: 4 }}>
                    <div style={{ height: "100%", width: `${strategy[dim.key]}%`, background: `linear-gradient(90deg, ${dim.color}80, ${dim.color})`, borderRadius: 4 }} />
                  </div>
                </div>
              ))}
              <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #1e3a5f" }}>
                <div style={{ color: "#64748b", fontSize: 10 }}>COMPOSITE SCORE</div>
                <div style={{ fontSize: 24, fontWeight: "bold", color: strategy.color }}>
                  {Math.round((strategy.securityScore + strategy.performanceScore + strategy.compatibilityScore) / 3)}%
                </div>
                {strategy.isProposed && (
                  <div style={{ color: "#10b981", fontSize: 10, marginTop: 4 }}>✦ Trilemma Broken — All dimensions ≥ 87%</div>
                )}
              </div>
            </div>

            {/* Phase simulation */}
            <div style={S.card}>
              <div style={S.cardTitle}>MIGRATION PHASES</div>
              {strategy.phases.map((phase, i) => (
                <div key={i} style={{
                  padding: "8px 10px", marginBottom: 6, borderRadius: 4,
                  background: i <= simStep ? `${strategy.color}18` : "#0a1424",
                  border: `1px solid ${i <= simStep ? strategy.color + "40" : "#1e3a5f"}`,
                  transition: "all 0.4s",
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ color: i <= simStep ? strategy.color : "#1e3a5f", fontSize: 14 }}>
                      {i < simStep ? "✓" : i === simStep && simRunning ? "" : "○"}
                    </span>
                    <span style={{ color: i <= simStep ? "#e2e8f0" : "#4a7fa5", fontSize: 11 }}>{phase}</span>
                  </div>
                </div>
              ))}
              <button onClick={startSim} disabled={simRunning}
                style={{
                  marginTop: 8, padding: "8px 16px", background: simRunning ? "#1e3a5f" : `${strategy.color}25`,
                  border: `1px solid ${strategy.color}60`, color: strategy.color,
                  borderRadius: 4, cursor: simRunning ? "not-allowed" : "pointer",
                  fontSize: 11, fontFamily: "monospace", width: "100%",
                }}>
                {simRunning ? "Simulating..." : "Run Simulation"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Strategy Comparison Matrix</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
            <thead>
              <tr>
                {["Strategy", "Security", "Performance", "Compatibility", "Risk", "Timeline", "Composite"].map(h => (
                  <th key={h} style={{ padding: "10px 12px", textAlign: "left", color: "#4a7fa5", borderBottom: "2px solid #1e3a5f", whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(MIGRATION_STRATEGIES).map(([name, s]) => {
                const composite = Math.round((s.securityScore + s.performanceScore + s.compatibilityScore) / 3);
                return (
                  <tr key={name}
                    onClick={() => setSelectedStrategy(name)}
                    style={{
                      borderBottom: "1px solid #0f2040", cursor: "pointer",
                      background: selectedStrategy === name ? `${s.color}10` : "transparent",
                    }}>
                    <td style={{ padding: "10px 12px", color: s.color, fontWeight: "bold" }}>
                      {s.isProposed ? "✦ " : ""}{name}
                    </td>
                    <td style={{ padding: "10px 12px", color: "#6ee7f7" }}>{s.securityScore}%</td>
                    <td style={{ padding: "10px 12px", color: "#a78bfa" }}>{s.performanceScore}%</td>
                    <td style={{ padding: "10px 12px", color: "#fbbf24" }}>{s.compatibilityScore}%</td>
                    <td style={{ padding: "10px 12px", color: s.risk === "Low" ? "#22c55e" : s.risk.startsWith("Medium") ? "#fbbf24" : "#ef4444" }}>{s.risk}</td>
                    <td style={{ padding: "10px 12px", color: "#94a3b8" }}>{s.timeEstimate}</td>
                    <td style={{ padding: "10px 12px", color: composite >= 85 ? "#10b981" : composite >= 65 ? "#fbbf24" : "#ef4444", fontWeight: "bold" }}>{composite}%</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  //ALGORITHM TAB
  const renderAlgorithms = () => {
    const metric = metricLabels[algoMetric];
    const filtered = Object.entries(PQC_ALGORITHMS).filter(([name]) => selectedAlgos.includes(name));
    const maxVal = Math.max(...filtered.map(([, a]) => a[algoMetric]));

    return (
      <div>
        <div style={S.card}>
          <div style={S.cardTitle}>⊕ Algorithm Selection</div>
          <div style={{ marginBottom: 12 }}>
            {Object.keys(PQC_ALGORITHMS).map(name => (
              <button key={name} style={S.algoChip(name, selectedAlgos)}
                onClick={() => toggleAlgo(name)}>
                {PQC_ALGORITHMS[name].quantumSafe ? "◈ " : "⚠ "}{name}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.keys(metricLabels).map(key => (
              <button key={key} onClick={() => setAlgoMetric(key)}
                style={{
                  padding: "5px 10px", borderRadius: 4, fontSize: 10,
                  cursor: "pointer", fontFamily: "monospace",
                  background: algoMetric === key ? "#6ee7f715" : "#0a1424",
                  border: `1px solid ${algoMetric === key ? "#6ee7f7" : "#1e3a5f"}`,
                  color: algoMetric === key ? "#6ee7f7" : "#64748b",
                }}>
                {metricLabels[key].label}
              </button>
            ))}
          </div>
        </div>

        <div style={S.grid2}>
          <div style={S.card}>
            <div style={S.cardTitle}>{metric.label} ({metric.unit})</div>
            {filtered.map(([name, algo]) => (
              <AlgoBar key={name} label={name.split(" ")[0] + " " + (name.split(" ")[1] || "")}
                value={algo[algoMetric]} max={maxVal * 1.1}
                color={algo.color} unit={metric.unit} />
            ))}
          </div>

          <div>
            {filtered.slice(0, 3).map(([name, algo]) => (
              <div key={name} style={{ ...S.card, borderColor: algo.color + "30", marginBottom: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <div>
                    <div style={{ color: algo.color, fontSize: 12, fontWeight: "bold" }}>{name}</div>
                    <div style={{ color: "#4a7fa5", fontSize: 10 }}>{algo.basis}</div>
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    {algo.quantumSafe && <span style={S.badge("#10b981")}>QSafe</span>}
                    {algo.classical && <span style={S.badge("#ef4444")}>Classical</span>}
                    {algo.nistLevel > 0 && <span style={S.badge("#6ee7f7")}>NIST L{algo.nistLevel}</span>}
                  </div>
                </div>
                <div style={S.grid2}>
                  {[
                    ["Pub Key", algo.pubKeyBytes + "B"],
                    ["Signature", algo.sigBytes + "B"],
                    ["Sign", algo.sign_ms + "ms"],
                    ["Verify", algo.verify_ms + "ms"],
                  ].map(([k, v]) => (
                    <div key={k} style={{ fontSize: 10 }}>
                      <span style={{ color: "#4a7fa5" }}>{k}: </span>
                      <span style={{ color: "#e2e8f0" }}>{v}</span>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 8, display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {algo.strengths.map(s => <span key={s} style={{ ...S.badge(algo.color), fontSize: 9 }}>{s}</span>)}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={S.card}>
          <div style={S.cardTitle}>Full Algorithm Comparison Table</div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
              <thead>
                <tr>
                  {["Algorithm", "Type", "Basis", "PubKey", "PrivKey", "Sig/CT", "Keygen(ms)", "Sign(ms)", "Verify(ms)", "NIST Level", "Quantum Safe"].map(h => (
                    <th key={h} style={{ padding: "8px", textAlign: "left", color: "#4a7fa5", borderBottom: "1px solid #1e3a5f", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(PQC_ALGORITHMS).map(([name, algo]) => (
                  <tr key={name} style={{ borderBottom: "1px solid #0a1424" }}>
                    <td style={{ padding: "8px", color: algo.color, fontWeight: "bold", whiteSpace: "nowrap" }}>{name}</td>
                    <td style={{ padding: "8px", color: "#94a3b8" }}>{algo.type}</td>
                    <td style={{ padding: "8px", color: "#64748b", whiteSpace: "nowrap" }}>{algo.basis}</td>
                    <td style={{ padding: "8px", color: "#e2e8f0" }}>{algo.pubKeyBytes}B</td>
                    <td style={{ padding: "8px", color: "#e2e8f0" }}>{algo.privKeyBytes}B</td>
                    <td style={{ padding: "8px", color: "#e2e8f0" }}>{algo.sigBytes}B</td>
                    <td style={{ padding: "8px", color: "#94a3b8" }}>{algo.keygen_ms}</td>
                    <td style={{ padding: "8px", color: "#94a3b8" }}>{algo.sign_ms}</td>
                    <td style={{ padding: "8px", color: "#94a3b8" }}>{algo.verify_ms}</td>
                    <td style={{ padding: "8px", color: "#6ee7f7" }}>{algo.nistLevel > 0 ? algo.nistLevel : "—"}</td>
                    <td style={{ padding: "8px", color: algo.quantumSafe ? "#10b981" : "#ef4444" }}>
                      {algo.quantumSafe ? "✓ YES" : "✗ NO"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // ── TRILEMMA TAB
  const renderTrilemma = () => (
    <div>
      <div style={S.card}>
        <div style={S.cardTitle}>The PQC Blockchain Migration Trilemma</div>
        <p style={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.8, margin: 0 }}>
          Analogous to the CAP theorem and the original Blockchain Trilemma (Buterin), migrating 
          existing blockchain systems to Post-Quantum Cryptography introduces a three-way 
          optimization conflict. No current approach simultaneously achieves all three properties — 
          until now.
        </p>
      </div>

      <div style={S.grid3}>
        {[
          {
            vertex: "Security",
            color: "#6ee7f7",
            definition: "Full quantum resistance against Shor's & Grover's algorithms at NIST Level 2+",
            tension: "PQC algorithms require large key/signature sizes and new cryptographic assumptions",
            metrics: ["NIST PQC Level ≥ 2", "Quantum bit security ≥ 128", "No classical fallback"],
          },
          {
            vertex: "Performance",
            color: "#a78bfa",
            definition: "Maintaining blockchain throughput, latency, and storage efficiency at scale",
            tension: "PQC signatures are 10-40× larger than ECDSA, increasing block size and verification cost",
            metrics: ["Sig size ≤ 2× ECDSA", "Verify time ≤ 2× ECDSA", "Block overhead ≤ 20%"],
          },
          {
            vertex: "Compatibility",
            color: "#fbbf24",
            definition: "Backward compatibility with existing wallets, nodes, DApps, and infrastructure",
            tension: "PQC algorithms incompatible with existing ECC-based address schemes and signature verification",
            metrics: ["0% hard fork required", "Legacy wallet support", "DApp continuity"],
          },
        ].map((v, i) => (
          <div key={i} style={{ ...S.card, borderColor: v.color + "30" }}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>{v.icon}</div>
            <div style={{ color: v.color, fontSize: 14, fontWeight: "bold", marginBottom: 8 }}>{v.vertex}</div>
            <div style={{ color: "#94a3b8", fontSize: 11, lineHeight: 1.6, marginBottom: 10 }}>{v.definition}</div>
            <div style={{ color: "#ef4444", fontSize: 10, marginBottom: 10, padding: "6px 8px", background: "#ef444410", borderRadius: 4, borderLeft: "2px solid #ef444440" }}>
              <span style={{ fontWeight: "bold" }}>Tension: </span>{v.tension}
            </div>
            <div>
              {v.metrics.map((m, j) => (
                <div key={j} style={{ fontSize: 10, color: v.color + "aa", marginBottom: 3 }}>◈ {m}</div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Why It's a Trilemma — Proof of Incompatibility</div>
        <div style={S.grid2}>
          {[
            {
              pair: "Security + Performance", color: "#ef4444",
              loses: "Compatibility",
              explanation: "Using raw Dilithium3 signatures achieves NIST Level 3 security and reasonable performance (~0.27ms sign), but requires new address formats and hard fork — existing wallets break.",
            },
            {
              pair: "Security + Compatibility", color: "#f97316",
              loses: "Performance",
              explanation: "Embedding PQC commitment in OP_RETURN maintains old nodes. But full SPHINCS+ signatures add 7856 bytes per tx — blockchain grows 40× faster. Impractical at scale.",
            },
            {
              pair: "Performance + Compatibility", color: "#fbbf24",
              loses: "Security",
              explanation: "Keeping ECDSA but adding lightweight wrappers maintains size and old node support. But offers zero quantum resistance — a CRQC can still forge signatures.",
            },
            {
              pair: "✦ AQMP Framework", color: "#10b981",
              loses: "None — Trilemma Broken",
              explanation: "ZK-aggregated PQC proofs + temporal decoupling + Dual-Commit Layer achieves 93% Security, 87% Performance, 91% Compatibility simultaneously. See AQMP tab.",
            },
          ].map((item, i) => (
            <div key={i} style={{ ...S.card, marginBottom: 0, borderColor: item.color + "30" }}>
              <div style={{ color: item.color, fontWeight: "bold", fontSize: 12, marginBottom: 6 }}>{item.pair}</div>
              <div style={{ color: "#ef4444", fontSize: 10, marginBottom: 6 }}>
                Sacrifices: <span style={{ fontWeight: "bold" }}>{item.loses}</span>
              </div>
              <div style={{ color: "#94a3b8", fontSize: 11, lineHeight: 1.6 }}>{item.explanation}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Related Trilemma Theorems</div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          {[
            { name: "CAP Theorem", dims: ["Consistency", "Availability", "Partition Tolerance"], origin: "Brewer, 2000" },
            { name: "Blockchain Trilemma", dims: ["Security", "Scalability", "Decentralization"], origin: "Buterin, 2017" },
            { name: "PQC Migration Trilemma", dims: ["Quantum Security", "Performance", "Compatibility"], origin: "This Paper, 2025", highlight: true },
          ].map((t, i) => (
            <div key={i} style={{
              ...S.card, marginBottom: 0, flex: 1, minWidth: 200,
              borderColor: t.highlight ? "#10b98140" : "#1e3a5f",
              background: t.highlight ? "#10b98108" : "#080f1e",
            }}>
              <div style={{ color: t.highlight ? "#10b981" : "#94a3b8", fontWeight: "bold", fontSize: 12, marginBottom: 4 }}>
                {t.highlight ? " " : ""}{t.name}
              </div>
              <div style={{ color: "#64748b", fontSize: 10, marginBottom: 8 }}>{t.origin}</div>
              <div style={{ display: "flex", gap: 4 }}>
                {t.dims.map((d, j) => (
                  <span key={j} style={{ ...S.badge(t.highlight ? "#10b981" : "#4a7fa5"), marginLeft: 0 }}>{d}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div style={S.root}>
      <div style={S.header}>
        <h1 style={S.title}>
          PQC BLOCKCHAIN MIGRATION TRILEMMA
          <span style={S.badge("#10b981")}>RESEARCH TOOL</span>
          <span style={S.badge("#6ee7f7")}>v1.0</span>
        </h1>
        <div style={S.subtitle}>
          Post-Quantum Cryptography · Migration Analysis · AQMP Framework · Trilemma Resolution
        </div>
      </div>
      <div style={S.nav}>
        {tabs.map(tab => (
          <button key={tab.id} style={S.tabBtn(activeTab === tab.id)}
            onClick={() => setActiveTab(tab.id)}>
            {tab.label}
          </button>
        ))}
      </div>
      <div style={S.content}>
        {activeTab === "trilemma" && renderTrilemma()}
        {activeTab === "algorithms" && renderAlgorithms()}
        {activeTab === "simulator" && renderSimulator()}
        {activeTab === "aqmp" && renderAQMP()}
        {activeTab === "threat" && renderThreat()}
      </div>
    </div>
  );
}