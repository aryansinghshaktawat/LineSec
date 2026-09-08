"use client";

import React, { useEffect, useState } from "react";
import { 
  Shield, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle, 
  ChevronDown, 
  ChevronUp, 
  RefreshCw,
  Terminal,
  Activity,
  AlertOctagon,
  FileCode,
  HeartPulse,
  Clock,
  Sparkles,
  GitPullRequest,
  Layers,
  Check,
  ArrowRight,
  Sliders,
  ShieldCheck,
  Zap,
  Flame
} from "lucide-react";

interface Finding {
  finding_id: string;
  tool_name: string;
  scanner?: string;
  vulnerability_name: string;
  cve?: string;
  severity: string;
  priority?: string;
  risk_score?: number;
  description: string;
  file_path: string;
  line_number: number;
  package?: string;
  installed_version?: string;
  fixed_version?: string;
  remediation_status: string;
  status?: string;
  root_cause?: string;
  remediation_plan?: string;
}

interface RemediationTask {
  task_id: string;
  title: string;
  package?: string;
  ecosystem?: string;
  action: string;
  target_version?: string;
  status: string;
  priority: string;
  risk_score?: number;
  safety_level: string;
  findings_count: number;
  decision?: {
    summary: string;
    recommended_action: string;
    deployment_risk: string;
    provider: string;
  };
}

interface PostureSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number;
  security_debt_hours: number;
  remediation_progress_percent: number;
  regressions_count: number;
}

interface SLAReport {
  active_tasks_count: number;
  breached_tasks_count: number;
  approaching_breach_count: number;
  on_track_tasks_count: number;
  waived_items_count: number;
  mttr_hours: number;
  priority_breakdown: Record<string, { total: number; breached: number; approaching: number; on_track: number }>;
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<"findings" | "tasks" | "diff" | "sla">("findings");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [posture, setPosture] = useState<PostureSummary | null>(null);
  const [slaReport, setSlaReport] = useState<SLAReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Risk Acceptance Form state
  const [waiverTaskId, setWaiverTaskId] = useState<string>("");
  const [waiverReason, setWaiverReason] = useState<string>("");
  const [waiverOwner, setWaiverOwner] = useState<string>("security-team@linesec.io");

  const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

  const fetchAllData = async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch Findings
      const findingsRes = await fetch(`${API_BASE}/api/findings`);
      if (!findingsRes.ok) {
        throw new Error(`Failed to fetch findings: ${findingsRes.status} ${findingsRes.statusText}`);
      }
      const data: Finding[] = await findingsRes.json();
      setFindings(data);

      // 2. Fetch Tasks
      const tasksRes = await fetch(`${API_BASE}/api/v1/tasks`);
      if (!tasksRes.ok) {
        throw new Error(`Failed to fetch remediation tasks: ${tasksRes.status} ${tasksRes.statusText}`);
      }
      const tasksData: RemediationTask[] = await tasksRes.json();
      setTasks(tasksData);

      // 3. Fetch Posture
      const postureRes = await fetch(`${API_BASE}/api/v1/posture`);
      if (!postureRes.ok) {
        throw new Error(`Failed to fetch security posture: ${postureRes.status} ${postureRes.statusText}`);
      }
      const pData: PostureSummary = await postureRes.json();
      setPosture(pData);

      // 4. Fetch SLA
      const slaRes = await fetch(`${API_BASE}/api/v1/posture/sla`);
      if (!slaRes.ok) {
        throw new Error(`Failed to fetch SLA report: ${slaRes.status} ${slaRes.statusText}`);
      }
      const sData: SLAReport = await slaRes.json();
      setSlaReport(sData);

    } catch (err: any) {
      setError(err.message || "Failed to communicate with LineSec API backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const handleGroupTasks = async () => {
    setActionMessage("Clustering vulnerabilities into remediation tasks...");
    try {
      const res = await fetch(`${API_BASE}/api/v1/tasks/group`, { method: "POST" });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Grouping failed with status ${res.status}`);
      }
      setActionMessage("Vulnerabilities successfully grouped into tasks!");
      await fetchAllData();
    } catch (err: any) {
      setError(`Task grouping error: ${err.message}`);
      setActionMessage(null);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleRemediateTask = async (taskId: string) => {
    setActionMessage(`Generating FixPlan and executing remediation for ${taskId}...`);
    try {
      const res = await fetch(`${API_BASE}/api/v1/tasks/${taskId}/remediate?dry_run=false`, { method: "POST" });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Remediation failed with status ${res.status}`);
      }
      const data = await res.json();
      setActionMessage(`Remediation executed: ${data.branch_name || taskId} (${data.status})`);
      await fetchAllData();
    } catch (err: any) {
      setError(`Remediation error for task ${taskId}: ${err.message}`);
      setActionMessage(null);
    }
    setTimeout(() => setActionMessage(null), 5000);
  };

  const handleVerifyTask = async (taskId: string) => {
    setActionMessage(`Running verification rescan against task ${taskId}...`);
    try {
      const res = await fetch(`${API_BASE}/api/v1/tasks/${taskId}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rescan_findings: [] })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Verification failed with status ${res.status}`);
      }
      const data = await res.json();
      setActionMessage(`Verification Complete: ${data.summary}`);
      await fetchAllData();
    } catch (err: any) {
      setError(`Verification error for task ${taskId}: ${err.message}`);
      setActionMessage(null);
    }
    setTimeout(() => setActionMessage(null), 5000);
  };

  const handleGrantWaiver = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!waiverTaskId || !waiverReason) return;
    setActionMessage("Granting formal Risk Acceptance waiver...");
    try {
      const expires = new Date();
      expires.setDate(expires.getDate() + 30);
      const res = await fetch(`${API_BASE}/api/v1/risk-acceptance`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: waiverTaskId,
          reason: waiverReason,
          owner: waiverOwner,
          expires_at: expires.toISOString()
        })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Risk waiver failed with status ${res.status}`);
      }
      setActionMessage("Risk Acceptance waiver granted!");
      setWaiverTaskId("");
      setWaiverReason("");
      await fetchAllData();
    } catch (err: any) {
      setError(`Risk waiver error: ${err.message}`);
      setActionMessage(null);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 sm:p-8">
      {/* Header */}
      <header className="max-w-7xl mx-auto mb-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="bg-rose-500/10 p-2.5 rounded-lg border border-rose-500/20 text-rose-500">
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-3xl font-extrabold tracking-tight text-white bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                LineSec 2+
              </h1>
              <span className="bg-rose-500/20 text-rose-300 text-xs px-2 py-0.5 rounded-full border border-rose-500/30 font-semibold uppercase tracking-wider">
                Enterprise DevSecOps
              </span>
            </div>
            <p className="text-slate-400 text-sm font-medium mt-0.5">
              Context-Aware Vulnerability Management, Automated Remediation & Verification
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={handleGroupTasks}
            className="flex items-center gap-2 px-3.5 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/30 rounded-lg text-sm text-indigo-300 font-semibold transition shadow-md"
          >
            <Layers className="w-4 h-4" />
            Group Tasks
          </button>

          <button 
            onClick={fetchAllData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-800 rounded-lg text-sm text-slate-300 font-semibold transition shadow-md disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </header>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div className="max-w-7xl mx-auto mb-6 p-4 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-300 text-sm flex items-center gap-3 animate-fade-in">
          <Zap className="w-5 h-5 text-indigo-400 flex-shrink-0" />
          <span className="font-semibold">{actionMessage}</span>
        </div>
      )}

      {/* Main Container */}
      <main className="max-w-7xl mx-auto space-y-8">
        
        {/* Posture & SLA Metrics Ribbon */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {/* Card 1: Security Posture Score */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-slate-700">
              <ShieldCheck className="w-8 h-8 opacity-40 text-indigo-400" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Security Score
            </p>
            <div className="flex items-baseline gap-2 mt-2">
              <h3 className={`text-3xl font-bold ${(posture?.security_score ?? 70) >= 80 ? 'text-emerald-400' : (posture?.security_score ?? 70) >= 60 ? 'text-amber-400' : 'text-rose-500'}`}>
                {posture?.security_score ?? 70.0}
              </h3>
              <span className="text-xs text-slate-500 font-medium">/ 100</span>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${(posture?.security_score ?? 70) >= 80 ? 'bg-emerald-500' : 'bg-amber-500'}`}
                style={{ width: `${posture?.security_score ?? 70}%` }}
              ></div>
            </div>
          </div>

          {/* Card 2: Security Debt Hours */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-amber-500">
              <Clock className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Security Debt
            </p>
            <div className="flex items-baseline gap-2 mt-2">
              <h3 className="text-3xl font-bold text-amber-400">
                {posture?.security_debt_hours ?? 6.0}h
              </h3>
              <span className="text-xs text-slate-500">MTTR: {slaReport?.mttr_hours ?? 4.2}h</span>
            </div>
            <p className="text-slate-500 text-xs mt-2">Estimated developer effort to resolve</p>
          </div>

          {/* Card 3: SLA Compliance & Breaches */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-rose-500">
              <Flame className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              SLA Governance
            </p>
            <div className="flex items-center gap-3 mt-2">
              <span className={`text-2xl font-bold ${(slaReport?.breached_tasks_count ?? 0) > 0 ? 'text-rose-500' : 'text-emerald-400'}`}>
                {slaReport?.breached_tasks_count ?? 0} Breached
              </span>
            </div>
            <p className="text-slate-500 text-xs mt-2">
              {slaReport?.approaching_breach_count ?? 0} approaching deadline (<span className="text-slate-400 font-mono">P0: 24h</span>)
            </p>
          </div>

          {/* Card 4: Remediation Progress */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-emerald-500">
              <CheckCircle className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Progress & Regressions
            </p>
            <div className="flex items-baseline gap-2 mt-2">
              <h3 className="text-3xl font-bold text-emerald-400">
                {posture?.remediation_progress_percent ?? 50.0}%
              </h3>
              <span className="text-xs text-rose-400 font-medium">{posture?.regressions_count ?? 0} regressed</span>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
              <div 
                className="bg-emerald-500 h-full rounded-full transition-all duration-500" 
                style={{ width: `${posture?.remediation_progress_percent ?? 50}%` }}
              ></div>
            </div>
          </div>
        </section>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 gap-6">
          <button
            onClick={() => setActiveTab("findings")}
            className={`pb-3 text-sm font-bold transition flex items-center gap-2 border-b-2 ${
              activeTab === "findings"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="w-4 h-4" />
            Vulnerabilities ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab("tasks")}
            className={`pb-3 text-sm font-bold transition flex items-center gap-2 border-b-2 ${
              activeTab === "tasks"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <GitPullRequest className="w-4 h-4" />
            Remediation Tasks ({tasks.length})
          </button>
          <button
            onClick={() => setActiveTab("diff")}
            className={`pb-3 text-sm font-bold transition flex items-center gap-2 border-b-2 ${
              activeTab === "diff"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sliders className="w-4 h-4" />
            Security Diffs & Verification
          </button>
          <button
            onClick={() => setActiveTab("sla")}
            className={`pb-3 text-sm font-bold transition flex items-center gap-2 border-b-2 ${
              activeTab === "sla"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Clock className="w-4 h-4" />
            SLA & Risk Waivers
          </button>
        </div>

        {/* Tab 1: Vulnerabilities Table */}
        {activeTab === "findings" && (
          <section className="bg-slate-900/40 border border-slate-800/60 rounded-xl overflow-hidden shadow-xl backdrop-blur-md">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-900/80 text-slate-400 text-xs font-bold uppercase border-b border-slate-800/80">
                    <th className="px-6 py-3.5">Priority</th>
                    <th className="px-6 py-3.5">Vulnerability / CVE</th>
                    <th className="px-6 py-3.5">Severity</th>
                    <th className="px-6 py-3.5">Risk Score</th>
                    <th className="px-6 py-3.5">Status</th>
                    <th className="px-6 py-3.5">Location</th>
                    <th className="w-12 py-3.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {findings.map((f) => {
                    const isExpanded = expandedId === f.finding_id;
                    const prio = f.priority || "P2";
                    const sev = (f.severity || "MEDIUM").toUpperCase();
                    const status = (f.status || f.remediation_status || "NEW").toUpperCase();
                    const risk = f.risk_score ?? 50.0;

                    return (
                      <React.Fragment key={f.finding_id}>
                        <tr 
                          onClick={() => toggleExpand(f.finding_id)}
                          className="hover:bg-slate-800/20 cursor-pointer transition border-b border-slate-850"
                        >
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center text-xs font-extrabold px-2.5 py-1 rounded-md font-mono ${
                              prio === "P0" ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" :
                              prio === "P1" ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" :
                              prio === "P2" ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" :
                              "bg-slate-800 text-slate-400 border border-slate-700"
                            }`}>
                              {prio}
                            </span>
                          </td>
                          <td className="px-6 py-4 font-semibold text-white">
                            <div>{f.vulnerability_name}</div>
                            {f.cve && <span className="text-xs text-slate-500 font-mono">{f.cve}</span>}
                          </td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center text-xs font-bold px-2 py-0.5 rounded ${
                              sev === "CRITICAL" ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" :
                              sev === "HIGH" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                              sev === "MEDIUM" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                              "bg-slate-500/10 text-slate-400 border border-slate-700/40"
                            }`}>
                              {sev}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="font-mono text-xs font-bold text-slate-200">{risk.toFixed(1)}</span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                              {status.replace("_", " ")}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-slate-400 text-sm font-mono flex items-center gap-1">
                            <FileCode className="w-4 h-4 text-slate-600 flex-shrink-0" />
                            <span className="truncate max-w-[200px]" title={f.file_path}>
                              {f.file_path || f.package || "N/A"}
                            </span>
                            {f.line_number > 0 && <span className="text-slate-300">:{f.line_number}</span>}
                          </td>
                          <td className="pr-6 py-4 text-right">
                            {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr className="bg-slate-900/20">
                            <td colSpan={7} className="px-6 py-5 border-t border-slate-800/30">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900/50 p-5 rounded-lg border border-slate-800/80">
                                <div>
                                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                                    Vulnerability Overview
                                  </h4>
                                  <p className="text-sm text-slate-300 leading-relaxed mb-3">
                                    {f.description}
                                  </p>
                                  {f.package && (
                                    <div className="text-xs font-mono text-slate-400 space-y-1">
                                      <div>Package: <span className="text-slate-200">{f.package}</span></div>
                                      <div>Installed: <span className="text-rose-400">{f.installed_version || "unpinned"}</span></div>
                                      <div>Target Fix: <span className="text-emerald-400">{f.fixed_version || "latest-secure"}</span></div>
                                    </div>
                                  )}
                                </div>
                                <div className="space-y-4">
                                  <div>
                                    <h4 className="text-xs font-bold text-teal-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                                      <Sparkles className="w-3.5 h-3.5" />
                                      AI Root Cause Analysis
                                    </h4>
                                    <p className="text-sm text-slate-300 leading-relaxed font-sans">
                                      {f.root_cause || "Pending automated reasoning..."}
                                    </p>
                                  </div>
                                  <div>
                                    <h4 className="text-xs font-bold text-sky-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                                      <Check className="w-3.5 h-3.5" />
                                      AI Remediation Guidance
                                    </h4>
                                    <p className="text-sm text-slate-300 leading-relaxed font-sans">
                                      {f.remediation_plan || "Pending automated FixPlan..."}
                                    </p>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Tab 2: Remediation Tasks & FixPlans */}
        {activeTab === "tasks" && (
          <section className="space-y-4">
            {tasks.map((task) => (
              <div key={task.task_id} className="bg-slate-900/50 border border-slate-800/80 p-6 rounded-xl shadow-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {task.priority}
                    </span>
                    <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                      task.safety_level === "SAFE" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                      task.safety_level === "APPROVAL_REQUIRED" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                      "bg-slate-800 text-slate-400"
                    }`}>
                      {task.safety_level}
                    </span>
                    <h3 className="text-lg font-bold text-white">{task.title}</h3>
                  </div>
                  <p className="text-sm text-slate-400">
                    Target: <code className="text-indigo-300 bg-indigo-950/40 px-1 rounded">{task.package || "Manifest"} {">="} {task.target_version}</code> • {task.findings_count} linked vulnerabilities
                  </p>
                  {task.decision && (
                    <p className="text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800">
                      💡 <strong>Decision:</strong> {task.decision.summary}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleRemediateTask(task.task_id)}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-semibold rounded-lg text-sm transition"
                  >
                    <GitPullRequest className="w-4 h-4" />
                    Open PR
                  </button>
                  <button
                    onClick={() => handleVerifyTask(task.task_id)}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/30 text-indigo-300 font-semibold rounded-lg text-sm transition"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    Verify Fix
                  </button>
                </div>
              </div>
            ))}
          </section>
        )}

        {/* Tab 3: Security Diffs & Verification */}
        {activeTab === "diff" && (
          <section className="bg-slate-900/40 border border-slate-800/60 p-6 rounded-xl space-y-6">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Sliders className="w-5 h-5 text-indigo-400" />
                Rescan Comparison & Verification Diff
              </h2>
              <p className="text-sm text-slate-400 mt-1">
                Deterministic fingerprint diffing across scans to verify vulnerability eradication.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div className="bg-slate-900/60 p-4 rounded-lg border border-emerald-500/20">
                <div className="text-xs font-semibold text-emerald-400 uppercase">Resolved</div>
                <div className="text-2xl font-bold text-white mt-1">1</div>
                <div className="text-xs text-slate-500 mt-1">Eradicated from codebase</div>
              </div>
              <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase">Unchanged</div>
                <div className="text-2xl font-bold text-white mt-1">1</div>
                <div className="text-xs text-slate-500 mt-1">Still open / active</div>
              </div>
              <div className="bg-slate-900/60 p-4 rounded-lg border border-amber-500/20">
                <div className="text-xs font-semibold text-amber-400 uppercase">New Introduced</div>
                <div className="text-2xl font-bold text-white mt-1">0</div>
                <div className="text-xs text-slate-500 mt-1">Fresh findings in rescan</div>
              </div>
              <div className="bg-slate-900/60 p-4 rounded-lg border border-rose-500/20">
                <div className="text-xs font-semibold text-rose-400 uppercase">Regressions</div>
                <div className="text-2xl font-bold text-white mt-1">0</div>
                <div className="text-xs text-slate-500 mt-1">Re-opened resolved flaws</div>
              </div>
            </div>
          </section>
        )}

        {/* Tab 4: SLA Governance & Risk Waivers */}
        {activeTab === "sla" && (
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800/60 p-6 rounded-xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Clock className="w-5 h-5 text-amber-400" />
                Enterprise SLA Targets & Timers
              </h3>
              <div className="space-y-3 text-sm">
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-rose-400">P0 (Critical / Emergency)</span>
                    <p className="text-xs text-slate-400">Max Resolution SLA: 24 Hours</p>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
                    100% Compliant
                  </span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-amber-400">P1 (High Priority)</span>
                    <p className="text-xs text-slate-400">Max Resolution SLA: 7 Days (168h)</p>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
                    On Track
                  </span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-blue-400">P2 (Medium Priority)</span>
                    <p className="text-xs text-slate-400">Max Resolution SLA: 30 Days (720h)</p>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
                    On Track
                  </span>
                </div>
              </div>
            </div>

            {/* Grant Waiver Form */}
            <div className="bg-slate-900/40 border border-slate-800/60 p-6 rounded-xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                Grant Risk Waiver
              </h3>
              <form onSubmit={handleGrantWaiver} className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Target Task ID</label>
                  <input
                    type="text"
                    value={waiverTaskId}
                    onChange={(e) => setWaiverTaskId(e.target.value)}
                    placeholder="e.g. task-demo-1"
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Business Rationale</label>
                  <textarea
                    value={waiverReason}
                    onChange={(e) => setWaiverReason(e.target.value)}
                    placeholder="Reason for temporary risk acceptance..."
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white h-20"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Approver Email</label>
                  <input
                    type="email"
                    value={waiverOwner}
                    onChange={(e) => setWaiverOwner(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                    required
                  />
                </div>
                <button
                  type="submit"
                  className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded transition"
                >
                  Record Formal Waiver
                </button>
              </form>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
