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
  HeartPulse
} from "lucide-react";

interface Finding {
  finding_id: string;
  tool_name: string;
  vulnerability_name: string;
  severity: string;
  description: string;
  file_path: string;
  line_number: number;
  remediation_status: string;
  root_cause?: string;
  remediation_plan?: string;
}

export default function Dashboard() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("http://127.0.0.1:8000/api/findings");
      if (!response.ok) {
        throw new Error(`Failed to fetch: ${response.statusText}`);
      }
      const data: Finding[] = await response.json();
      setFindings(data);
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  // Metrics calculations
  const totalVulnerabilities = findings.length;
  
  const criticalCount = findings.filter(
    (f) => f.severity.toUpperCase() === "CRITICAL"
  ).length;
  
  const highCount = findings.filter(
    (f) => f.severity.toUpperCase() === "HIGH"
  ).length;

  const ticketOpenedCount = findings.filter(
    (f) => f.remediation_status.toUpperCase() === "TICKET_OPENED"
  ).length;

  const remediationProgress = totalVulnerabilities > 0 
    ? Math.round((ticketOpenedCount / totalVulnerabilities) * 100) 
    : 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 sm:p-8">
      {/* Header */}
      <header className="max-w-7xl mx-auto mb-8 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="bg-rose-500/10 p-2.5 rounded-lg border border-rose-500/20 text-rose-500">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-3xl font-extrabold tracking-tight text-white bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                LineSec Platform
              </h1>
              <p className="text-slate-400 text-sm font-medium mt-0.5">
                Continuous Application Security Monitoring
              </p>
            </div>
          </div>
        </div>
        
        <button 
          onClick={fetchFindings}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-800 rounded-lg text-sm text-slate-300 font-semibold transition duration-200 shadow-md shadow-black/20 hover:shadow-lg disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Refreshing...' : 'Refresh Data'}
        </button>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto space-y-8">
        
        {/* Metrics Row */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {/* Card 1: Total Vulnerabilities */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-slate-700">
              <Activity className="w-8 h-8 opacity-40" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Total Vulnerabilities
            </p>
            <h3 className="text-3xl font-bold mt-2 text-white">
              {loading ? "..." : totalVulnerabilities}
            </h3>
            <p className="text-slate-500 text-xs mt-2">Active security issues detected</p>
          </div>

          {/* Card 2: Critical Severity */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-rose-500">
              <ShieldAlert className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Critical Severity
            </p>
            <h3 className="text-3xl font-bold mt-2 text-rose-500">
              {loading ? "..." : criticalCount}
            </h3>
            <p className="text-slate-500 text-xs mt-2">Requires immediate attention</p>
          </div>

          {/* Card 3: High Severity */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-amber-500">
              <AlertTriangle className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              High Severity
            </p>
            <h3 className="text-3xl font-bold mt-2 text-amber-500">
              {loading ? "..." : highCount}
            </h3>
            <p className="text-slate-500 text-xs mt-2">Requires high-priority patching</p>
          </div>

          {/* Card 4: Remediation Progress */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden backdrop-blur-md">
            <div className="absolute right-4 top-4 text-emerald-500">
              <CheckCircle className="w-8 h-8 opacity-30" />
            </div>
            <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
              Remediation Progress
            </p>
            <h3 className="text-3xl font-bold mt-2 text-emerald-400">
              {loading ? "..." : `${remediationProgress}%`}
            </h3>
            
            {/* Custom progress bar */}
            <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
              <div 
                className="bg-emerald-500 h-full rounded-full transition-all duration-500" 
                style={{ width: `${remediationProgress}%` }}
              ></div>
            </div>
            <p className="text-slate-500 text-[10px] mt-1.5">
              {ticketOpenedCount} of {totalVulnerabilities} issues ticketed
            </p>
          </div>
        </section>

        {/* Database findings table */}
        <section className="bg-slate-900/40 border border-slate-800/60 rounded-xl overflow-hidden shadow-xl backdrop-blur-md">
          <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-indigo-400" />
              Detected Vulnerabilities
            </h2>
            <span className="bg-slate-800 text-slate-300 text-xs px-2.5 py-1 rounded-full font-semibold border border-slate-700">
              {findings.length} findings
            </span>
          </div>

          {error && (
            <div className="p-6 bg-rose-500/10 border-b border-rose-500/20 text-rose-400 text-sm flex items-center gap-3">
              <AlertOctagon className="w-5 h-5 flex-shrink-0" />
              <div>
                <span className="font-bold">Error loading findings:</span> {error}. Make sure the backend server at <code className="bg-rose-500/20 px-1 rounded text-white">http://127.0.0.1:8000</code> is running.
              </div>
            </div>
          )}

          {loading ? (
            <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
              <RefreshCw className="w-8 h-8 animate-spin text-slate-600" />
              <p className="font-semibold text-sm">Querying secure findings database...</p>
            </div>
          ) : findings.length === 0 ? (
            <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
              <HeartPulse className="w-12 h-12 text-slate-700" />
              <p className="font-semibold text-base text-slate-400">No vulnerabilities detected</p>
              <p className="text-xs text-slate-500">Run security scan pipelines to populate security data.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-900/80 text-slate-400 text-xs font-bold uppercase border-b border-slate-800/80">
                    <th className="px-6 py-3.5">Tool</th>
                    <th className="px-6 py-3.5">Vulnerability</th>
                    <th className="px-6 py-3.5">Severity</th>
                    <th className="px-6 py-3.5">Status</th>
                    <th className="px-6 py-3.5">File Path & Line</th>
                    <th className="w-12 py-3.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {findings.map((finding) => {
                    const isExpanded = expandedId === finding.finding_id;
                    const severity = finding.severity.toUpperCase();
                    const status = finding.remediation_status.toUpperCase();

                    return (
                      <React.Fragment key={finding.finding_id}>
                        {/* Main row */}
                        <tr 
                          onClick={() => toggleExpand(finding.finding_id)}
                          className="hover:bg-slate-800/20 cursor-pointer transition duration-155 border-b border-slate-850"
                        >
                          <td className="px-6 py-4">
                            <span className="bg-slate-800 text-slate-300 text-xs px-2.5 py-1 rounded font-mono border border-slate-700/60 uppercase">
                              {finding.tool_name}
                            </span>
                          </td>
                          <td className="px-6 py-4 font-semibold text-white">
                            {finding.vulnerability_name}
                          </td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center text-xs font-bold px-2 py-0.5 rounded ${
                              severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                              severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                              severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                              'bg-slate-500/10 text-slate-400 border border-slate-700/40'
                            }`}>
                              {severity}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full ${
                              status === 'TICKET_OPENED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                              status === 'ANALYZED' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                              'bg-slate-800 text-slate-400 border border-slate-700'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${
                                status === 'TICKET_OPENED' ? 'bg-emerald-400' :
                                status === 'ANALYZED' ? 'bg-blue-400' :
                                'bg-slate-500'
                              }`}></span>
                              {status.replace("_", " ")}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-slate-400 text-sm font-mono flex items-center gap-1">
                            <FileCode className="w-4 h-4 text-slate-600 flex-shrink-0" />
                            <span className="truncate max-w-[200px] sm:max-w-xs" title={finding.file_path}>
                              {finding.file_path}
                            </span>
                            <span className="text-slate-600 font-bold">:</span>
                            <span className="text-slate-300">{finding.line_number}</span>
                          </td>
                          <td className="pr-6 py-4 text-right">
                            {isExpanded ? (
                              <ChevronUp className="w-5 h-5 text-slate-500" />
                            ) : (
                              <ChevronDown className="w-5 h-5 text-slate-500" />
                            )}
                          </td>
                        </tr>

                        {/* Expandable details row */}
                        {isExpanded && (
                          <tr className="bg-slate-900/20">
                            <td colSpan={6} className="px-6 py-5 border-t border-slate-800/30">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900/50 p-5 rounded-lg border border-slate-800/80">
                                <div>
                                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                                    Vulnerability Description
                                  </h4>
                                  <p className="text-sm text-slate-300 leading-relaxed">
                                    {finding.description}
                                  </p>
                                </div>
                                <div className="space-y-4">
                                  <div>
                                    <h4 className="text-xs font-bold text-teal-400 uppercase tracking-wider mb-1">
                                      AI Root Cause Analysis
                                    </h4>
                                    <p className="text-sm text-slate-300 leading-relaxed font-sans">
                                      {finding.root_cause || "Pending analysis from LineSec AI engine..."}
                                    </p>
                                  </div>
                                  <div>
                                    <h4 className="text-xs font-bold text-sky-400 uppercase tracking-wider mb-1">
                                      AI Suggested Remediation Plan
                                    </h4>
                                    <p className="text-sm text-slate-300 leading-relaxed font-sans">
                                      {finding.remediation_plan || "Pending remediation plan from LineSec AI engine..."}
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
          )}
        </section>
      </main>
    </div>
  );
}
