import { useState, useEffect, useRef } from "react";

const AGENTS = [
  { id: "detection", label: "Detection Agent", icon: "ti-radar", color: "#1A56DB", bg: "rgba(26,86,219,0.12)", border: "rgba(26,86,219,0.35)", role: "Anomaly Identification", desc: "Isolation Forest · LSTM · ChromaDB RAG" },
  { id: "investigation", label: "Investigation Agent", icon: "ti-brain", color: "#8B5CF6", bg: "rgba(139,92,246,0.12)", border: "rgba(139,92,246,0.35)", role: "Hypothesis Generation", desc: "LLaMA 3 · SSE · MITRE ATT&CK" },
  { id: "response", label: "Response Agent", icon: "ti-shield-bolt", color: "#10B981", bg: "rgba(16,185,129,0.12)", border: "rgba(16,185,129,0.35)", role: "Automated Remediation", desc: "RSEM Scoring · SOAR · Dry-run Engine" },
  { id: "reporting", label: "Reporting Agent", icon: "ti-file-analytics", color: "#06B6D4", bg: "rgba(6,182,212,0.12)", border: "rgba(6,182,212,0.35)", role: "Explainable AI (XAI)", desc: "LLaMA 3 · D3.js · Audit Log Writer" },
];

const INCIDENTS_SEED = [
  { id: "INC-2026-041", time: "14:32:07", severity: "CRITICAL", type: "Credential Dumping", host: "ws-fin-27", score: 87, confidence: 92, mitre: "T1003", status: "ISOLATED", zone: 2, chain: ["Login Anomaly","Lateral Movement","Privilege Escalation","Data Exfil Attempt"] },
  { id: "INC-2026-040", time: "13:58:44", severity: "HIGH", type: "Brute Force SSH", host: "srv-db-03", score: 61, confidence: 78, mitre: "T1110", status: "BLOCKED", zone: 2, chain: ["Port Scan","SSH Auth Failure","Auth Failure Spike"] },
  { id: "INC-2026-039", time: "13:21:19", severity: "MEDIUM", type: "Anomalous DNS Query", host: "ws-hr-11", score: 34, confidence: 65, mitre: "T1071", status: "MONITORING", zone: 1, chain: ["Beaconing Detected","DNS Exfil Suspect"] },
  { id: "INC-2026-038", time: "12:47:02", severity: "HIGH", type: "Lateral Movement", host: "ws-dev-05", score: 72, confidence: 85, mitre: "T1021", status: "ISOLATED", zone: 2, chain: ["Internal RDP","Credential Reuse","Suspicious Process"] },
  { id: "INC-2026-037", time: "11:03:55", severity: "LOW", type: "Failed Login Attempts", host: "ws-mkt-08", score: 18, confidence: 45, mitre: "T1078", status: "MONITORING", zone: 1, chain: ["Failed Auth"] },
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#EF4444", bg: "rgba(239,68,68,0.15)", border: "rgba(239,68,68,0.4)" },
  HIGH:     { color: "#F97316", bg: "rgba(249,115,22,0.15)", border: "rgba(249,115,22,0.4)" },
  MEDIUM:   { color: "#F59E0B", bg: "rgba(245,158,11,0.15)", border: "rgba(245,158,11,0.4)" },
  LOW:      { color: "#10B981", bg: "rgba(16,185,129,0.15)", border: "rgba(16,185,129,0.4)" },
};

const STATUS_CONFIG = {
  ISOLATED:   { color: "#EF4444", label: "Isolated" },
  BLOCKED:    { color: "#F97316", label: "Blocked" },
  MONITORING: { color: "#F59E0B", label: "Monitoring" },
  CLEARED:    { color: "#10B981", label: "Cleared" },
};

const ZONE_CONFIG = {
  1: { color: "#EF4444", label: "Zone 1 — Full Oversight",    desc: "All actions require approval" },
  2: { color: "#F59E0B", label: "Zone 2 — Semi-Autonomous",   desc: "Low-risk auto, high-risk manual" },
  3: { color: "#10B981", label: "Zone 3 — Autonomous",        desc: "Mostly autonomous, all logged" },
};

function AttackChainViz({ chain }) {
  const colors = ["#EF4444","#F97316","#8B5CF6","#EF4444","#06B6D4"];
  return (
    <svg width="100%" viewBox={`0 0 ${chain.length * 130 + 20} 60`} style={{ overflow:"visible" }}>
      <defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
          <path d="M0,0 L0,6 L6,3 z" fill="#4B5563" />
        </marker>
      </defs>
      {chain.map((node, i) => {
        const x = i * 130 + 10;
        const col = colors[i % colors.length];
        return (
          <g key={i}>
            {i > 0 && <line x1={x-20} y1={30} x2={x} y2={30} stroke="#4B5563" strokeWidth={1.5} markerEnd="url(#arrow)" />}
            <rect x={x} y={12} width={110} height={36} rx={6} fill={col+"22"} stroke={col} strokeWidth={1} />
            <text x={x+55} y={28} textAnchor="middle" fill={col} fontSize={9} fontWeight="600" fontFamily="monospace">{`T${i+1}`}</text>
            <text x={x+55} y={41} textAnchor="middle" fill="#C8D8FF" fontSize={8.5} fontFamily="sans-serif">
              {node.length > 14 ? node.slice(0,13)+"…" : node}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

function AgentStatusDot({ active }) {
  return (
    <span style={{ display:"inline-block", width:8, height:8, borderRadius:"50%",
      background: active ? "#10B981" : "#4B5563",
      boxShadow: active ? "0 0 6px #10B981" : "none",
      marginRight:6, flexShrink:0 }} />
  );
}

function ScoreRing({ score, color, size=52 }) {
  const r = (size-8)/2;
  const circ = 2*Math.PI*r;
  const dash = (score/100)*circ;
  return (
    <svg width={size} height={size} style={{ flexShrink:0 }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={4} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={4}
        strokeDasharray={`${dash} ${circ-dash}`} strokeLinecap="round"
        transform={`rotate(-90 ${size/2} ${size/2})`} />
      <text x={size/2} y={size/2+4} textAnchor="middle" fill={color} fontSize={11} fontWeight="700" fontFamily="monospace">{score}</text>
    </svg>
  );
}

function LiveAlertTicker({ incidents }) {
  const [idx, setIdx] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setIdx(i => (i+1) % incidents.length), 3000);
    return () => clearInterval(t);
  }, [incidents.length]);
  const inc = incidents[idx];
  const sev = SEVERITY_CONFIG[inc.severity];
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 14px",
      background:"rgba(6,182,212,0.06)", border:"1px solid rgba(6,182,212,0.2)", borderRadius:8, fontSize:12 }}>
      <span style={{ color:"#06B6D4", fontWeight:700, letterSpacing:1, fontSize:10 }}>LIVE</span>
      <span style={{ width:1, height:14, background:"rgba(255,255,255,0.15)" }} />
      <span style={{ color:sev.color, fontWeight:600 }}>{inc.severity}</span>
      <span style={{ color:"#9DB0D8" }}>{inc.type}</span>
      <span style={{ color:"#5A6E8A" }}>on</span>
      <span style={{ color:"#C8D8FF", fontFamily:"monospace" }}>{inc.host}</span>
      <span style={{ color:"#5A6E8A", marginLeft:"auto" }}>{inc.time}</span>
    </div>
  );
}

export default function SynthetixSOC() {
  const [activeTab, setActiveTab]   = useState("dashboard");
  const [selectedInc, setSelectedInc] = useState(INCIDENTS_SEED[0]);
  const [zone, setZone]             = useState(2);
  const [agentTick, setAgentTick]   = useState(0);
  const [incidents]                 = useState(INCIDENTS_SEED);
  const [liveStats, setLiveStats]   = useState({ alerts:47, blocked:12, investigated:31, mttd:8.3 });

  useEffect(() => {
    const t = setInterval(() => {
      setAgentTick(n => n+1);
      setLiveStats(s => ({
        alerts:       s.alerts + Math.floor(Math.random()*2),
        blocked:      s.blocked + (Math.random()>0.7 ? 1 : 0),
        investigated: s.investigated + (Math.random()>0.5 ? 1 : 0),
        mttd:         Math.max(5, +(s.mttd+(Math.random()-0.5)*0.3).toFixed(1)),
      }));
    }, 2500);
    return () => clearInterval(t);
  }, []);

  const activeAgentIdx = agentTick % 4;

  const TABS = [
    { id:"dashboard",  label:"Dashboard",  icon:"ti-layout-dashboard" },
    { id:"incidents",  label:"Incidents",  icon:"ti-alert-triangle" },
    { id:"agents",     label:"Agents",     icon:"ti-cpu" },
    { id:"xai",        label:"XAI Panel",  icon:"ti-report-analytics" },
    { id:"governance", label:"Governance", icon:"ti-shield-check" },
  ];

  return (
    <div style={{ background:"#060E22", minHeight:"100vh", fontFamily:"'Segoe UI',system-ui,sans-serif", color:"#F0F4FF", fontSize:13 }}>

      {/* ── HEADER ── */}
      <div style={{ background:"linear-gradient(135deg,#04122E 0%,#0D1B4B 100%)", borderBottom:"1px solid rgba(100,140,255,0.18)", padding:"14px 20px", display:"flex", alignItems:"center", gap:16 }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:32, height:32, borderRadius:8, background:"rgba(6,182,212,0.2)", border:"1px solid rgba(6,182,212,0.5)", display:"flex", alignItems:"center", justifyContent:"center" }}>
            <i className="ti ti-shield-lock" style={{ fontSize:18, color:"#06B6D4" }} />
          </div>
          <div>
            <div style={{ fontWeight:800, fontSize:15, letterSpacing:1, color:"#60A5FA" }}>SYNTHeTiX-SOC</div>
            <div style={{ fontSize:9, color:"#8899CC", letterSpacing:2, textTransform:"uppercase" }}>Autonomous Multi-Agent Security Platform</div>
          </div>
        </div>
        <div style={{ flex:1 }}><LiveAlertTicker incidents={incidents} /></div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          <span style={{ fontSize:10, padding:"3px 10px", borderRadius:12,
            background: ZONE_CONFIG[zone].color+"22",
            border:`1px solid ${ZONE_CONFIG[zone].color}66`,
            color: ZONE_CONFIG[zone].color, fontWeight:700 }}>
            {ZONE_CONFIG[zone].label}
          </span>
          <div style={{ width:8, height:8, borderRadius:"50%", background:"#10B981" }} />
          <span style={{ fontSize:11, color:"#6EE7B7" }}>LIVE</span>
        </div>
      </div>

      {/* ── NAV ── */}
      <div style={{ background:"#0D1B4B", borderBottom:"1px solid rgba(100,140,255,0.15)", display:"flex", padding:"0 20px", overflowX:"auto" }}>
        {TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            padding:"12px 18px", fontSize:12, fontWeight:500, cursor:"pointer",
            color: activeTab===tab.id ? "#06B6D4" : "#8899CC",
            border:"none", background:"none",
            borderBottom: activeTab===tab.id ? "2px solid #06B6D4" : "2px solid transparent",
            transition:"all 0.2s", fontFamily:"inherit", display:"flex", alignItems:"center", gap:6, whiteSpace:"nowrap"
          }}>
            <i className={`ti ${tab.icon}`} style={{ fontSize:15 }} />
            {tab.label}
          </button>
        ))}
      </div>

      <div style={{ padding:20 }}>

        {/* ══ DASHBOARD ══ */}
        {activeTab==="dashboard" && (
          <div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:20 }}>
              {[
                { label:"Total Alerts Today",  val:liveStats.alerts,       color:"#06B6D4", icon:"ti-alert-circle" },
                { label:"Threats Blocked",      val:liveStats.blocked,      color:"#10B981", icon:"ti-shield-check" },
                { label:"Auto-Investigated",    val:liveStats.investigated, color:"#8B5CF6", icon:"ti-brain" },
                { label:"Avg MTTD (min)",       val:liveStats.mttd,         color:"#F59E0B", icon:"ti-clock" },
              ].map((s,i) => (
                <div key={i} style={{ background:"rgba(255,255,255,0.04)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:"14px 16px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
                    <i className={`ti ${s.icon}`} style={{ fontSize:16, color:s.color }} />
                    <span style={{ fontSize:10, color:"#8899CC", textTransform:"uppercase", letterSpacing:1 }}>{s.label}</span>
                  </div>
                  <div style={{ fontSize:28, fontWeight:800, color:s.color, lineHeight:1 }}>{s.val}</div>
                </div>
              ))}
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:16 }}>
              <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
                <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:12 }}>Live Agent Pipeline</div>
                <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                  {AGENTS.map((agent,i) => {
                    const isActive = i===activeAgentIdx;
                    const isDone   = i<activeAgentIdx;
                    return (
                      <div key={agent.id} style={{ display:"flex", alignItems:"center", gap:12, padding:"10px 14px", borderRadius:8,
                        border:`1px solid ${isActive ? agent.color+"80" : "rgba(100,140,255,0.12)"}`,
                        background: isActive ? agent.bg : "rgba(255,255,255,0.02)", transition:"all 0.4s" }}>
                        <div style={{ width:36, height:36, borderRadius:8,
                          background: isActive ? agent.bg : "rgba(255,255,255,0.04)",
                          border:`1px solid ${isActive ? agent.border : "rgba(100,140,255,0.18)"}`,
                          display:"flex", alignItems:"center", justifyContent:"center" }}>
                          <i className={`ti ${agent.icon}`} style={{ fontSize:18, color:isActive ? agent.color : "#4B6080" }} />
                        </div>
                        <div style={{ flex:1 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                            <AgentStatusDot active={isActive||isDone} />
                            <span style={{ fontWeight:700, fontSize:13, color:isActive ? agent.color : isDone ? "#C8D8FF" : "#4B6080" }}>{agent.label}</span>
                          </div>
                          <div style={{ fontSize:11, color:"#5A6E8A", marginTop:2 }}>{agent.desc}</div>
                        </div>
                        <div style={{ fontSize:10, padding:"2px 8px", borderRadius:8,
                          background: isActive ? agent.color+"33" : isDone ? "rgba(16,185,129,0.15)" : "rgba(255,255,255,0.04)",
                          border:`1px solid ${isActive ? agent.color+"60" : isDone ? "rgba(16,185,129,0.3)" : "rgba(100,140,255,0.12)"}`,
                          color: isActive ? agent.color : isDone ? "#6EE7B7" : "#4B6080" }}>
                          {isActive ? "RUNNING" : isDone ? "DONE" : "WAITING"}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
                <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:12 }}>Recent Incidents</div>
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {incidents.slice(0,5).map(inc => {
                    const sev = SEVERITY_CONFIG[inc.severity];
                    return (
                      <div key={inc.id} onClick={() => { setSelectedInc(inc); setActiveTab("xai"); }}
                        style={{ padding:"8px 10px", borderRadius:7, border:`1px solid ${sev.border}`, background:sev.bg, cursor:"pointer" }}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                          <span style={{ fontSize:10, fontFamily:"monospace", color:"#8899CC" }}>{inc.id}</span>
                          <span style={{ fontSize:10, color:sev.color, fontWeight:700 }}>{inc.severity}</span>
                        </div>
                        <div style={{ fontSize:12, fontWeight:600, color:"#C8D8FF", marginBottom:2 }}>{inc.type}</div>
                        <div style={{ fontSize:10, color:"#5A6E8A" }}>{inc.host} · {inc.time}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div style={{ marginTop:16, background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:12 }}>
                <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2 }}>Latest Attack Chain — {incidents[0].id}</div>
                <span style={{ fontSize:10, color:"#EF4444", padding:"2px 8px", borderRadius:8, background:"rgba(239,68,68,0.15)", border:"1px solid rgba(239,68,68,0.35)" }}>MITRE {incidents[0].mitre}</span>
              </div>
              <AttackChainViz chain={incidents[0].chain} />
            </div>
          </div>
        )}

        {/* ══ INCIDENTS ══ */}
        {activeTab==="incidents" && (
          <div>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
              <div>
                <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:4 }}>Incident Queue</div>
                <div style={{ fontSize:18, fontWeight:700 }}>Active Security Incidents</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {incidents.map(inc => {
                const sev  = SEVERITY_CONFIG[inc.severity];
                const stat = STATUS_CONFIG[inc.status];
                return (
                  <div key={inc.id} onClick={() => { setSelectedInc(inc); setActiveTab("xai"); }}
                    style={{ padding:"14px 16px", borderRadius:10, border:`1px solid ${sev.border}`, background:sev.bg, cursor:"pointer", display:"flex", alignItems:"center", gap:16 }}>
                    <ScoreRing score={inc.score} color={sev.color} />
                    <div style={{ flex:1 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
                        <span style={{ fontSize:12, fontFamily:"monospace", color:"#8899CC" }}>{inc.id}</span>
                        <span style={{ fontSize:10, padding:"2px 8px", borderRadius:8, background:sev.color+"33", border:`1px solid ${sev.color}60`, color:sev.color, fontWeight:700 }}>{inc.severity}</span>
                        <span style={{ fontSize:10, padding:"2px 8px", borderRadius:8, background:"rgba(255,255,255,0.05)", border:"1px solid rgba(100,140,255,0.2)", color:"#8899CC" }}>Zone {inc.zone}</span>
                      </div>
                      <div style={{ fontSize:14, fontWeight:700, color:"#C8D8FF", marginBottom:4 }}>{inc.type}</div>
                      <div style={{ display:"flex", gap:16, fontSize:11, color:"#5A6E8A" }}>
                        <span>{inc.host}</span>
                        <span>{inc.time}</span>
                        <span>MITRE {inc.mitre}</span>
                        <span>Confidence {inc.confidence}%</span>
                      </div>
                    </div>
                    <div style={{ textAlign:"right" }}>
                      <div style={{ fontSize:11, color:stat.color, fontWeight:700, marginBottom:6 }}>{stat.label}</div>
                      <div style={{ fontSize:10, color:"#4B6080" }}>View XAI →</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ══ AGENTS ══ */}
        {activeTab==="agents" && (
          <div>
            <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:4 }}>Multi-Agent System</div>
            <div style={{ fontSize:18, fontWeight:700, marginBottom:16 }}>The 4 Specialized Agents</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              {AGENTS.map((agent,i) => (
                <div key={agent.id} style={{ padding:18, borderRadius:10, border:`1px solid ${agent.border}`, background:agent.bg, position:"relative", overflow:"hidden" }}>
                  <div style={{ position:"absolute", top:10, right:14, fontSize:42, fontWeight:800, opacity:0.08, color:agent.color, lineHeight:1 }}>0{i+1}</div>
                  <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                    <div style={{ width:42, height:42, borderRadius:10, background:agent.color+"22", border:`1px solid ${agent.border}`, display:"flex", alignItems:"center", justifyContent:"center" }}>
                      <i className={`ti ${agent.icon}`} style={{ fontSize:22, color:agent.color }} />
                    </div>
                    <div>
                      <div style={{ fontSize:10, color:agent.color, textTransform:"uppercase", letterSpacing:1, marginBottom:2 }}>{agent.role}</div>
                      <div style={{ fontWeight:700, fontSize:14, color:"#C8D8FF" }}>{agent.label}</div>
                    </div>
                  </div>
                  <div style={{ fontSize:12, color:"#7A90B8", marginBottom:10, lineHeight:1.6 }}>{agent.desc}</div>
                  <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <AgentStatusDot active={i===activeAgentIdx} />
                    <span style={{ fontSize:11, color:i===activeAgentIdx ? agent.color : "#4B6080" }}>
                      {i===activeAgentIdx ? "Processing..." : i<activeAgentIdx ? "Standby" : "Waiting"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <div style={{ marginTop:14, padding:16, borderRadius:10, border:"1px solid rgba(245,158,11,0.35)", background:"rgba(245,158,11,0.06)" }}>
              <div style={{ fontSize:10, color:"#FCD34D", textTransform:"uppercase", letterSpacing:2, marginBottom:8 }}>LangGraph Orchestration</div>
              <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                {AGENTS.map((agent,i) => (
                  <div key={agent.id} style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <span style={{ fontSize:11, padding:"3px 10px", borderRadius:8, background:agent.color+"22", border:`1px solid ${agent.border}`, color:agent.color }}>{agent.label.split(" ")[0]}</span>
                    {i<AGENTS.length-1 && <span style={{ color:"#06B6D4", fontSize:16 }}>→</span>}
                  </div>
                ))}
                <span style={{ fontSize:11, color:"#5A6E8A", marginLeft:8 }}>· Full reasoning trace saved at every checkpoint</span>
              </div>
            </div>
          </div>
        )}

        {/* ══ XAI PANEL ══ */}
        {activeTab==="xai" && selectedInc && (
          <div>
            <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:4 }}>Explainable AI Panel</div>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
              <div style={{ fontSize:18, fontWeight:700 }}>{selectedInc.id} — {selectedInc.type}</div>
              <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                {incidents.map(inc => (
                  <button key={inc.id} onClick={() => setSelectedInc(inc)} style={{
                    fontSize:10, padding:"3px 10px", borderRadius:8,
                    border:`1px solid ${selectedInc.id===inc.id ? SEVERITY_CONFIG[inc.severity].color+"80" : "rgba(100,140,255,0.2)"}`,
                    background: selectedInc.id===inc.id ? SEVERITY_CONFIG[inc.severity].color+"22" : "transparent",
                    color: selectedInc.id===inc.id ? SEVERITY_CONFIG[inc.severity].color : "#8899CC",
                    cursor:"pointer", fontFamily:"inherit" }}>
                    {inc.id.replace("INC-2026-","#")}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 320px", gap:16, marginBottom:16 }}>
              <div style={{ background:"#060E22", border:"1px solid rgba(6,182,212,0.3)", borderRadius:10, padding:18 }}>
                <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:12 }}>AI Decision Explanation</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:10, marginBottom:14 }}>
                  <div style={{ textAlign:"center", padding:"10px", background:"rgba(255,255,255,0.03)", borderRadius:8, border:"1px solid rgba(100,140,255,0.15)" }}>
                    <div style={{ fontSize:10, color:"#8899CC", marginBottom:4 }}>Risk Score</div>
                    <ScoreRing score={selectedInc.score} color={SEVERITY_CONFIG[selectedInc.severity].color} size={48} />
                  </div>
                  <div style={{ textAlign:"center", padding:"10px", background:"rgba(255,255,255,0.03)", borderRadius:8, border:"1px solid rgba(100,140,255,0.15)" }}>
                    <div style={{ fontSize:10, color:"#8899CC", marginBottom:6 }}>Confidence</div>
                    <div style={{ fontSize:24, fontWeight:800, color:"#10B981" }}>{selectedInc.confidence}%</div>
                  </div>
                  <div style={{ textAlign:"center", padding:"10px", background:"rgba(255,255,255,0.03)", borderRadius:8, border:"1px solid rgba(100,140,255,0.15)" }}>
                    <div style={{ fontSize:10, color:"#8899CC", marginBottom:6 }}>MITRE ID</div>
                    <div style={{ fontSize:18, fontWeight:800, color:"#8B5CF6", fontFamily:"monospace" }}>{selectedInc.mitre}</div>
                  </div>
                </div>
                <div style={{ fontSize:10, color:"#67E8F9", fontWeight:700, marginBottom:6 }}>Why was this action taken?</div>
                <div style={{ fontSize:12, color:"#9DB0D8", lineHeight:1.75, background:"rgba(6,182,212,0.05)", border:"1px solid rgba(6,182,212,0.15)", borderRadius:8, padding:12 }}>
                  "{selectedInc.host} was flagged because it exhibited <strong style={{ color:"#C8D8FF" }}>{selectedInc.type}</strong> behavior (MITRE {selectedInc.mitre}) with {selectedInc.confidence}% confidence. The anomaly score of {selectedInc.score}/100 exceeded the Zone {selectedInc.zone} threshold. This matches the lateral movement pattern seen in 2 prior incidents. Action taken: host <strong style={{ color:"#C8D8FF" }}>{STATUS_CONFIG[selectedInc.status].label.toLowerCase()}</strong> — executed within Zone {selectedInc.zone} governance policy."
                </div>
                <div style={{ display:"flex", gap:8, marginTop:10, flexWrap:"wrap" }}>
                  <span style={{ fontSize:10, padding:"3px 10px", borderRadius:8, background:"rgba(16,185,129,0.15)", border:"1px solid rgba(16,185,129,0.3)", color:"#6EE7B7" }}>✓ Zone {selectedInc.zone} Approved</span>
                  <span style={{ fontSize:10, padding:"3px 10px", borderRadius:8, background:"rgba(245,158,11,0.15)", border:"1px solid rgba(245,158,11,0.3)", color:"#FCD34D" }}>↩ Rollback Available</span>
                  <span style={{ fontSize:10, padding:"3px 10px", borderRadius:8, background:"rgba(139,92,246,0.15)", border:"1px solid rgba(139,92,246,0.3)", color:"#C4B5FD" }}>Audit Logged</span>
                </div>
              </div>

              <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:14 }}>
                  <div style={{ fontSize:10, color:"#8899CC", textTransform:"uppercase", letterSpacing:1, marginBottom:10 }}>Incident Details</div>
                  {[["Host",selectedInc.host],["Detected",selectedInc.time],["Severity",selectedInc.severity],["Status",selectedInc.status],["Governance Zone",`Zone ${selectedInc.zone}`]].map(([k,v]) => (
                    <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"6px 0", borderBottom:"1px solid rgba(100,140,255,0.08)", fontSize:12 }}>
                      <span style={{ color:"#5A6E8A" }}>{k}</span>
                      <span style={{ color:"#C8D8FF", fontFamily:k==="Host"?"monospace":"inherit", fontWeight:600 }}>{v}</span>
                    </div>
                  ))}
                </div>
                <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:14 }}>
                  <div style={{ fontSize:10, color:"#8899CC", textTransform:"uppercase", letterSpacing:1, marginBottom:8 }}>Agent Reasoning Steps</div>
                  {["Detection Agent flagged 3σ deviation","ChromaDB retrieved 2 similar incidents","Investigation Agent generated 3 hypotheses","SSE validated network path feasibility","RSEM scored action → Zone gate passed","Response executed with dry-run first","Reporting Agent wrote XAI explanation"].map((step,i) => (
                    <div key={i} style={{ display:"flex", gap:8, alignItems:"flex-start", padding:"4px 0", fontSize:11, color:"#7A90B8" }}>
                      <span style={{ width:18, height:18, borderRadius:"50%", background:"rgba(6,182,212,0.15)", border:"1px solid rgba(6,182,212,0.3)", color:"#67E8F9", fontSize:9, fontWeight:700, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>{i+1}</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
              <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:12 }}>Attack Chain Visualization</div>
              <AttackChainViz chain={selectedInc.chain} />
            </div>
          </div>
        )}

        {/* ══ GOVERNANCE ══ */}
        {activeTab==="governance" && (
          <div>
            <div style={{ fontSize:10, color:"#06B6D4", textTransform:"uppercase", letterSpacing:2, marginBottom:4 }}>Governance Controls</div>
            <div style={{ fontSize:18, fontWeight:700, marginBottom:16 }}>Zoned Governance — Progressive Trust Model</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:20 }}>
              {[1,2,3].map(z => {
                const zc = ZONE_CONFIG[z];
                const isActive = zone===z;
                return (
                  <div key={z} onClick={() => setZone(z)} style={{ padding:18, borderRadius:10,
                    border:`2px solid ${isActive ? zc.color : zc.color+"44"}`,
                    background: isActive ? zc.color+"15" : zc.color+"08", cursor:"pointer", transition:"all 0.2s" }}>
                    <div style={{ fontSize:32, fontWeight:800, color:zc.color, opacity:0.25, lineHeight:1, float:"right" }}>{z}</div>
                    <div style={{ fontSize:14, fontWeight:700, color:"#C8D8FF", marginBottom:4 }}>Zone {z}</div>
                    <div style={{ fontSize:11, color:zc.color, fontWeight:600, marginBottom:8 }}>{["Full Human Oversight","Semi-Autonomous","Mostly Autonomous"][z-1]}</div>
                    <div style={{ fontSize:12, color:"#7A90B8", marginBottom:10, lineHeight:1.6 }}>{zc.desc}</div>
                    {isActive && <div style={{ fontSize:10, color:zc.color, fontWeight:700, padding:"3px 10px", background:zc.color+"22", border:`1px solid ${zc.color}60`, borderRadius:8, display:"inline-block" }}>ACTIVE</div>}
                  </div>
                );
              })}
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
                <div style={{ fontSize:10, color:"#8899CC", textTransform:"uppercase", letterSpacing:1, marginBottom:12 }}>Pending Human Approval</div>
                {[
                  { action:"Isolate ws-hr-11",    risk:34, type:"Host Isolation" },
                  { action:"Block 192.168.1.45",  risk:22, type:"IP Block" },
                ].map((item,i) => (
                  <div key={i} style={{ padding:"10px 12px", borderRadius:8, border:"1px solid rgba(245,158,11,0.3)", background:"rgba(245,158,11,0.07)", marginBottom:8, display:"flex", alignItems:"center", gap:12 }}>
                    <div style={{ flex:1 }}>
                      <div style={{ fontSize:12, fontWeight:600, color:"#C8D8FF", marginBottom:2 }}>{item.action}</div>
                      <div style={{ fontSize:11, color:"#5A6E8A" }}>{item.type} · Risk {item.risk}/100</div>
                    </div>
                    <div style={{ display:"flex", gap:6 }}>
                      <button style={{ fontSize:10, padding:"4px 10px", borderRadius:6, border:"1px solid rgba(16,185,129,0.5)", background:"rgba(16,185,129,0.15)", color:"#6EE7B7", cursor:"pointer", fontFamily:"inherit" }}>Approve</button>
                      <button style={{ fontSize:10, padding:"4px 10px", borderRadius:6, border:"1px solid rgba(239,68,68,0.5)", background:"rgba(239,68,68,0.15)", color:"#FCA5A5", cursor:"pointer", fontFamily:"inherit" }}>Reject</button>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(100,140,255,0.18)", borderRadius:10, padding:16 }}>
                <div style={{ fontSize:10, color:"#8899CC", textTransform:"uppercase", letterSpacing:1, marginBottom:12 }}>Audit Log (Immutable)</div>
                {[
                  { action:"Host ws-fin-27 isolated",      time:"14:32:07", hash:"a8f3c..." },
                  { action:"IP 10.0.1.22 blocked",         time:"13:58:44", hash:"c7e1d..." },
                  { action:"MFA enforced — srv-db-03",     time:"13:21:19", hash:"f2a9b..." },
                  { action:"Session revoked — ws-dev-05",  time:"12:47:02", hash:"d4e8c..." },
                ].map((log,i) => (
                  <div key={i} style={{ padding:"7px 0", borderBottom:"1px solid rgba(100,140,255,0.08)", display:"flex", alignItems:"center", gap:10, fontSize:11 }}>
                    <i className="ti ti-lock" style={{ fontSize:13, color:"#4B6080" }} />
                    <span style={{ flex:1, color:"#9DB0D8" }}>{log.action}</span>
                    <span style={{ color:"#5A6E8A", fontFamily:"monospace", fontSize:10 }}>{log.hash}</span>
                    <span style={{ color:"#4B6080" }}>{log.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
