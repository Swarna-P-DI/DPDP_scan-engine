import React, { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { getCoreReport, getLogs, getResult, getStatus, searchPii, startScan, summarizeLogs } from "../api";

import Overview from "../components/Overview";
import { buildReportContext } from "../utils/reportBuilder";

const ActionCenter = lazy(() => import("../components/ActionCenter"));
const CoreIntelligence = lazy(() => import("../components/CoreIntelligence"));
const DataQuality = lazy(() => import("../components/DataQuality"));
const Download = lazy(() => import("../components/Download"));
const DQCharts = lazy(() => import("../components/DQCharts"));
const GapAnalysis = lazy(() => import("../components/GapAnalysis"));
const InsightsPanel = lazy(() => import("../components/InsightsPanel"));
const Mapping = lazy(() => import("../components/Mapping"));
const Raid = lazy(() => import("../components/Raid"));
const RelationshipGraph = lazy(() => import("../components/RelationshipGraph"));
const Report = lazy(() => import("../components/Report"));
const Reviewer = lazy(() => import("../components/Reviewer"));
const RunHistory = lazy(() => import("../components/RunHistory"));

const POLL_INTERVAL_MS = 2000;

const tabs = [
  { id: "intelligence", label: "Intelligence" },
  { id: "overview", label: "Overview" },
  { id: "quality", label: "Quality" },
  { id: "mapping", label: "Inventory" },
  { id: "gaps", label: "Findings" },
  { id: "raid", label: "RayIN : RAID Master" },
  { id: "report", label: "Report" },
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const topBarStatus = (value) => {
  const normalized = String(value || "idle").toLowerCase();
  return normalized === "completed_scan_outputs" ? "completed" : normalized;
};

function PanelFallback() {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>Loading</h2>
          <p>Preparing dashboard panels.</p>
        </div>
      </div>
    </section>
  );
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [data, setData] = useState(null);
  const [coreReport, setCoreReport] = useState(null);
  const [logs, setLogs] = useState([]);
  const [searchQuery, setSearchQuery] = useState("Aadhaar");
  const [searchResult, setSearchResult] = useState(null);
  const [summaryPrompt, setSummaryPrompt] = useState("Summarize high-risk PII exposures");
  const [summaryResult, setSummaryResult] = useState(null);
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("idle");
  const [tasks, setTasks] = useState([]);
  const [rawStatus, setRawStatus] = useState(null);
  const [inspectTarget, setInspectTarget] = useState(null);

  const effectiveData = data || coreReport;
  const isFileScan = false;
  const tableCount = useMemo(() => Object.keys(data?.schema || {}).length, [data]);
  const context = useMemo(() => (data && rawStatus ? buildReportContext(data, rawStatus) : null), [data, rawStatus]);
  const model = context?.model || null;
  const visibleTabs = useMemo(() => (data ? tabs : tabs.filter((tab) => tab.id === "intelligence" || tab.id === "report")), [data]);
  const issueCount = useMemo(() => {
    if (model) return model.summary.issueCount;
    if (coreReport) return coreReport.summary?.findings ?? coreReport.pii_index?.length ?? 0;
    const tableIssues = data?.dq_report?.table_wise_issues || [];
    const gapIssues = data?.gap_analysis?.gaps || [];
    return tableIssues.length + gapIssues.length;
  }, [data, model, coreReport]);
  const displayStatus = topBarStatus(status);

  const loadCoreIntelligence = async () => {
    setError("");
    try {
      const [reportResponse, logsResponse] = await Promise.all([
        getCoreReport(),
        getLogs().catch(() => ({ data: [] })),
      ]);
      setCoreReport(reportResponse.data);
      setLogs(logsResponse.data || []);
      if (!data) {
        setStatus(reportResponse.data?.summary?.status || "loaded");
        setActiveTab("intelligence");
      }
    } catch (loadError) {
      setError(loadError.response?.data?.detail || loadError.message || "Unable to load backend intelligence");
    }
  };

  useEffect(() => {
    loadCoreIntelligence();
  }, []);

  const createAction = (action, context) => {
    const table = context?.table || "";
    const column = context?.column || "";
    const issueType = context?.issueType || action.type;
    const owner = context?.owner || "Data Engineering / Data Steward";
    const priority = action.priority || context?.priority || (context?.severity === "high" ? "high" : "medium");
    const group = priority === "high" ? "critical" : priority === "medium" ? "improvement" : "observation";
    const task = {
      id: `${table}|${column}|${issueType}|${action.type}`.toLowerCase(),
      task: action.label,
      table,
      column,
      owner,
      status: "OPEN",
      priority,
      group,
      summary: `${context?.label || "Scan item"} - ${context?.summary || ""}`.trim(),
    };

    setTasks((current) => {
      if (current.some((item) => item.id === task.id)) {
        return current;
      }
      return [task, ...current];
    });
  };

  const updateTaskStatus = (taskId, nextStatus) => {
    setTasks((current) =>
      current.map((task) => (task.id === taskId ? { ...task, status: nextStatus } : task))
    );
  };

  const inspectIssue = (item) => {
    setInspectTarget({
      table: item.table || "",
      column: item.column || "",
      summary: item.description || item.summary || "",
    });
    setActiveTab("mapping");
  };

  const runScan = async () => {
    setLoading(true);
    setError("");
    setData(null);
    setRawStatus(null);
    setTasks([]);
    setInspectTarget(null);
    setStatus("starting");

    try {
      const scanResponse = await startScan();
      const nextJobId = scanResponse.data.job_id;
      setJobId(nextJobId);

      let nextStatus = "running";
      let completedStatusPayload = null;
      while (nextStatus === "running" || nextStatus === "starting") {
        const statusResponse = await getStatus(nextJobId);
        nextStatus = statusResponse.data.status;
        setStatus(nextStatus);

        if (nextStatus === "failed") {
          throw new Error(statusResponse.data.error || "Scan failed");
        }

        if (nextStatus === "completed") {
          completedStatusPayload = statusResponse.data;
          break;
        }
        await sleep(POLL_INTERVAL_MS);
      }

      const resultResponse = completedStatusPayload || (await getResult(nextJobId)).data;
      const payload = resultResponse.result;
      if (!payload) throw new Error(resultResponse.error || "No scan result returned");

      setRawStatus(resultResponse);
      setData(payload);
      await loadCoreIntelligence();
      setActiveTab("intelligence");
    } catch (scanError) {
      setStatus("failed");
      setError(scanError.response?.data?.detail || scanError.message || "Unable to run scan");
    } finally {
      setLoading(false);
    }
  };

  const runSearch = async () => {
    if (!searchQuery.trim()) return;
    setError("");
    try {
      const response = await searchPii(searchQuery);
      setSearchResult(response.data);
      const logsResponse = await getLogs().catch(() => ({ data: [] }));
      setLogs(logsResponse.data || []);
    } catch (searchError) {
      setError(searchError.response?.data?.detail || searchError.message || "Unable to search PII index");
    }
  };

  const runSummary = async () => {
    if (!summaryPrompt.trim()) return;
    setError("");
    try {
      const response = await summarizeLogs(summaryPrompt);
      setSummaryResult(response.data);
    } catch (summaryError) {
      setError(summaryError.response?.data?.detail || summaryError.message || "Unable to summarize logs");
    }
  };

  return (
    <main className="dashboard-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Automated Data Discovery Platform</p>
          <h1>Scan Dashboard</h1>
        </div>
        <div className="scan-actions">
          <button className="primary-action" disabled={loading} onClick={runScan}>
            {loading ? "Running Platform Scan" : "Run Platform Scan"}
          </button>
          <button className="ghost-action" disabled={loading} onClick={loadCoreIntelligence}>
            Refresh Intelligence
          </button>
        </div>
      </section>

      <section className="status-strip">
        <div>
          <span className="metric-label">Job</span>
          <strong>{jobId || "Not started"}</strong>
        </div>
        <div>
          <span className="metric-label">Status</span>
          <strong className={`status-pill status-${displayStatus}`}>{displayStatus}</strong>
        </div>
        <div>
          <span className="metric-label">Final Score</span>
          <strong>{data?.scores?.final_score ?? coreReport?.summary?.findings ?? "Pending"}</strong>
        </div>
        <div>
          <span className="metric-label">Tables</span>
          <strong>{data ? tableCount : coreReport?.summary?.sources_scanned ?? "Pending"}</strong>
        </div>
        <div>
          <span className="metric-label">Issues</span>
          <strong>{data ? issueCount : "Pending"}</strong>
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}

      {!effectiveData && !loading && !error && (
        <section className="empty-state">
          <h2>Loading backend intelligence</h2>
          <p>The dashboard reads existing scan outputs and connector metadata automatically.</p>
        </section>
      )}

      {loading && (
        <section className="empty-state">
          <div className="loader" />
          <h2>Scan in progress</h2>
          <p>The backend is processing source inventory, profiling, data quality, findings, RayIN analysis, and report export.</p>
        </section>
      )}

      {effectiveData && (
        <>
          <nav className="tabs" aria-label="Dashboard sections">
            {visibleTabs.map((tab) => (
              <button
                className={activeTab === tab.id ? "tab active" : "tab"}
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          <section className="dashboard-content">
            {activeTab === "overview" && (
              <Suspense fallback={<PanelFallback />}>
                {data && model ? (
                  <>
                    <Overview data={data} model={model} />
                    <InsightsPanel insights={context.aiInsights} />
                    <DQCharts profiling={data.profiling} dq={data.dq_report} />
                    <RelationshipGraph relationships={model.relationships} />
                    <ActionCenter tasks={tasks} onInspectTask={inspectIssue} onUpdateTask={updateTaskStatus} />
                    <RunHistory diff={data.diff} />
                    <Download context={context} jobId={jobId} />
                  </>
                ) : <CoreIntelligence report={coreReport} logs={logs} searchQuery={searchQuery} searchResult={searchResult} summaryPrompt={summaryPrompt} summaryResult={summaryResult} onSearchQueryChange={setSearchQuery} onSearch={runSearch} onSummaryPromptChange={setSummaryPrompt} onSummarize={runSummary} />}
              </Suspense>
            )}
            {activeTab === "intelligence" && (
              <Suspense fallback={<PanelFallback />}>
                <CoreIntelligence report={coreReport || data} logs={logs} searchQuery={searchQuery} searchResult={searchResult} summaryPrompt={summaryPrompt} summaryResult={summaryResult} onSearchQueryChange={setSearchQuery} onSearch={runSearch} onSummaryPromptChange={setSummaryPrompt} onSummarize={runSummary} />
              </Suspense>
            )}
            {activeTab === "quality" && (
              <Suspense fallback={<PanelFallback />}>
                <DataQuality data={data.dq_report} profiling={data.profiling} />
              </Suspense>
            )}
            {activeTab === "mapping" && (
              <Suspense fallback={<PanelFallback />}>
                <Mapping initialFocus={inspectTarget} model={model} onCreateAction={createAction} />
              </Suspense>
            )}
            {activeTab === "gaps" && (
              <Suspense fallback={<PanelFallback />}>
                <GapAnalysis data={data.gap_analysis} model={model} onCreateAction={createAction} onInspect={inspectIssue} />
              </Suspense>
            )}
            {activeTab === "raid" && (
              <Suspense fallback={<PanelFallback />}>
                {data && model ? <Raid data={data.raid} model={model} onCreateAction={createAction} onInspect={inspectIssue} /> : <CoreIntelligence report={coreReport} logs={logs} searchQuery={searchQuery} searchResult={searchResult} summaryPrompt={summaryPrompt} summaryResult={summaryResult} onSearchQueryChange={setSearchQuery} onSearch={runSearch} onSummaryPromptChange={setSummaryPrompt} onSummarize={runSummary} />}
              </Suspense>
            )}
            {activeTab === "report" && (
              <Suspense fallback={<PanelFallback />}>
                {data && context ? (
                  <>
                    <Reviewer data={data} />
                    <Download context={context} jobId={jobId} />
                    <Report context={context} />
                  </>
                ) : <CoreIntelligence report={coreReport} logs={logs} searchQuery={searchQuery} searchResult={searchResult} summaryPrompt={summaryPrompt} summaryResult={summaryResult} onSearchQueryChange={setSearchQuery} onSearch={runSearch} onSummaryPromptChange={setSummaryPrompt} onSummarize={runSummary} />}
              </Suspense>
            )}
          </section>
        </>
      )}
    </main>
  );
}
