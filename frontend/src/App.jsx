import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import "./index.css";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:5000";

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "⌂" },
  { id: "threat", label: "Threat", icon: "📈" },
  { id: "baseline", label: "Baseline", icon: "🧠" },
  { id: "repository", label: "Access Control", icon: "🔒" },
  { id: "analysis", label: "Analysis", icon: "🎯" },
  { id: "timeline", label: "Timeline", icon: "📜" },
  { id: "architecture", label: "Architecture", icon: "🏗️" },
  { id: "events", label: "Events", icon: "📡" },
];

function App() {
  const [events, setEvents] = useState([]);
  const [systemOnline, setSystemOnline] = useState(false);
  const [tokenRevoked, setTokenRevoked] = useState(false);
  const [loadingAction, setLoadingAction] = useState("");

  const [repositoryFiles, setRepositoryFiles] = useState([]);
  const [repositoryMessage, setRepositoryMessage] = useState(
    "Repository has not been checked yet."
  );
  const [repositoryLoading, setRepositoryLoading] = useState(false);
  const [repositoryAccessState, setRepositoryAccessState] =
    useState("unchecked");

  const [activeSection, setActiveSection] = useState("overview");
  const [architectureOpen, setArchitectureOpen] = useState(false);

  const fetchEvents = useCallback(async () => {
    try {
      const [eventsResponse, statusResponse] = await Promise.all([
        axios.get(`${API_URL}/events`, { timeout: 5000 }),
        axios.get(`${API_URL}/status`, { timeout: 5000 }),
      ]);

      setEvents(Array.isArray(eventsResponse.data) ? eventsResponse.data : []);
      setTokenRevoked(Boolean(statusResponse.data.tokenRevoked));
      setSystemOnline(true);
    } catch (error) {
      console.error(
        "Failed to connect to backend:",
        error.response?.data || error.message
      );
      setSystemOnline(false);
    }
  }, []);

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 2000);
    return () => clearInterval(interval);
  }, [fetchEvents]);

  useEffect(() => {
    const sections = NAV_ITEMS.map((item) =>
      document.getElementById(item.id)
    ).filter(Boolean);

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

        if (visible.length > 0) {
          setActiveSection(visible[0].target.id);
        }
      },
      {
        rootMargin: "-30% 0px -55% 0px",
        threshold: [0.08, 0.2, 0.4],
      }
    );

    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  const scrollToSection = (id) => {
    const section = document.getElementById(id);
    if (!section) return;

    section.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  const simulateAttack = async () => {
    try {
      setLoadingAction("attack");

      await axios.post(
        `${API_URL}/simulate-attack`,
        {},
        { timeout: 10000 }
      );

      await fetchEvents();

      setRepositoryFiles([]);
      setRepositoryAccessState("unchecked");
      setRepositoryMessage(
        "Attack detected. Fetch the repository again to verify blocked access."
      );
    } catch (error) {
      console.error(
        "Attack simulation failed:",
        error.response?.data || error.message
      );
    } finally {
      setLoadingAction("");
    }
  };

  const resetDemo = async () => {
    try {
      setLoadingAction("reset");

      await axios.post(`${API_URL}/reset`, {}, { timeout: 10000 });

      setRepositoryFiles([]);
      setRepositoryMessage("Repository has not been checked yet.");
      setRepositoryAccessState("unchecked");

      await fetchEvents();
      scrollToSection("overview");
    } catch (error) {
      console.error(
        "Demo reset failed:",
        error.response?.data || error.message
      );
    } finally {
      setLoadingAction("");
    }
  };

  const fetchRepositoryFiles = async () => {
    try {
      setRepositoryLoading(true);
      setRepositoryMessage("Checking repository access...");

      const response = await axios.get(`${API_URL}/files`, {
        timeout: 10000,
      });

      const files = Array.isArray(response.data) ? response.data : [];

      setRepositoryFiles(files);
      setRepositoryAccessState("allowed");

      setRepositoryMessage(
        files.length > 0
          ? "Repository access successful. The GitHub token is active."
          : "Repository access successful, but no files were returned."
      );
    } catch (error) {
      setRepositoryFiles([]);

      if (error.response?.status === 401) {
        setRepositoryAccessState("blocked");
        setRepositoryMessage(
          "401 Unauthorized — credential quarantined by ShadowGuard AI."
        );
      } else {
        setRepositoryAccessState("error");
        setRepositoryMessage(
          error.response?.data?.error ||
            "Failed to fetch repository files."
        );
      }
    } finally {
      setRepositoryLoading(false);
    }
  };

  const latestEvent =
    events.length > 0 ? events[events.length - 1] : null;

  const latestRahulEvent = [...events]
    .reverse()
    .find((event) => event.agent === "Developer Rahul");

  const latestAgentEvent = [...events]
    .reverse()
    .find((event) => event.agent === "GitHub AI Agent");

  const latestHighRiskEvent = [...events]
    .reverse()
    .find((event) => event.risk === "HIGH");

  const activeIncidentEvent =
    tokenRevoked && latestHighRiskEvent
      ? latestHighRiskEvent
      : latestEvent;

  const compromisedIdentity =
    latestHighRiskEvent?.agent || null;

  const rahulHighRisk =
    latestRahulEvent?.risk === "HIGH" ||
    (tokenRevoked &&
      compromisedIdentity === "Developer Rahul");

  const agentHighRisk =
    latestAgentEvent?.risk === "HIGH" ||
    (tokenRevoked &&
      compromisedIdentity === "GitHub AI Agent");

  const hasHighRisk = events.some(
    (event) => event.risk === "HIGH"
  );

  const hasMediumRisk = events.some(
    (event) => event.risk === "MEDIUM"
  );

  const threatLevel = hasHighRisk
    ? "HIGH"
    : hasMediumRisk
      ? "MEDIUM"
      : "LOW";

  const requestCount =
    Number(activeIncidentEvent?.requestCount) || 0;

  const currentThreshold =
    Number(activeIncidentEvent?.threshold) || 5;

  const baselineExceeded =
    Boolean(activeIncidentEvent?.baselineExceeded) ||
    requestCount > currentThreshold;

  const mlAvailable =
    Boolean(activeIncidentEvent?.mlAvailable);

  const mlPrediction =
    activeIncidentEvent?.mlPrediction ||
    (events.length > 0 ? "UNAVAILABLE" : "NO DATA");

  const mlIsAnomaly =
    Boolean(activeIncidentEvent?.mlIsAnomaly);

  const mlAnomalyScore =
    Number(activeIncidentEvent?.mlAnomalyScore) || 0;

  const hybridRiskScore =
    Number(activeIncidentEvent?.combinedRiskScore) || 0;

  const mlModel =
    activeIncidentEvent?.mlModel || "Isolation Forest";

  const uniqueFiles =
    Number(activeIncidentEvent?.features?.uniqueFiles) || 0;

  const failedRequests =
    Number(activeIncidentEvent?.features?.failedRequests) || 0;

  const sensitiveFileAccesses =
    Number(activeIncidentEvent?.features?.sensitiveFileAccesses) || 0;

  const activityExplanation = !mlAvailable
    ? "No ML activity data available"
    : mlIsAnomaly
      ? "Suspicious file-access pattern detected"
      : baselineExceeded
        ? "Normal access pattern, but request volume exceeded baseline"
        : "Normal file-access behaviour detected";

  const activityDetails = !mlAvailable
    ? "Run a monitored activity test to view the ML explanation."
    : mlIsAnomaly
      ? `${uniqueFiles} files accessed • ${failedRequests} failed requests • ${sensitiveFileAccesses} sensitive-file accesses`
      : baselineExceeded
        ? `${requestCount} requests observed against a baseline of ${currentThreshold} • ML prediction remained NORMAL`
        : `${uniqueFiles} files accessed • ${failedRequests} failed requests • ${sensitiveFileAccesses} sensitive-file accesses`;

  const threatData = useMemo(() => {
    return events.map((event, index) => {
      const count = Number(event.requestCount) || 0;
      const threshold = Number(event.threshold) || 5;

      const calculatedBaselineScore =
        count <= threshold
          ? Math.round((count / threshold) * 55)
          : Math.min(100, 70 + (count - threshold) * 10);

      const backendScore = Number(event.combinedRiskScore);

      const score = Number.isFinite(backendScore)
        ? backendScore
        : calculatedBaselineScore;

      return {
        eventNumber: index + 1,
        score,
        risk: event.risk,
        action: event.action,
        agent: event.agent,
        threshold,
        requestCount: count,
        mlPrediction: event.mlPrediction || "NO DATA",
        mlAnomalyScore: Number(event.mlAnomalyScore) || 0,
        combinedRiskScore: Number.isFinite(backendScore)
          ? backendScore
          : score,
      };
    });
  }, [events]);

  const activeBackendScore =
    activeIncidentEvent?.combinedRiskScore;

  const hasActiveBackendScore =
    activeBackendScore !== undefined &&
    activeBackendScore !== null &&
    Number.isFinite(Number(activeBackendScore));

  const currentThreatScore = hasActiveBackendScore
    ? Number(activeBackendScore)
    : threatData.length > 0
      ? threatData[threatData.length - 1].score
      : 0;

  const repositoryPanelState =
    repositoryAccessState === "blocked" || tokenRevoked
      ? "repository-blocked"
      : repositoryAccessState === "allowed"
        ? "repository-allowed"
        : "repository-neutral";

  const protectedAssetCount =
    repositoryFiles.length > 0 || tokenRevoked ? 1 : 0;

  const decisionConditions = [
    baselineExceeded,
    mlIsAnomaly,
    tokenRevoked,
  ];

  const matchedDecisionConditions =
    decisionConditions.filter(Boolean).length;

  const totalDecisionConditions = decisionConditions.length;

  const decisionConditionValue =
    `${matchedDecisionConditions}/${totalDecisionConditions}`;

  return (
    <div className="app">
      <header className="dashboard-header">
        <div className="brand-section">
          <div className="brand-mark">SG</div>
          <div>
            <h1>ShadowGuard AI</h1>
            <p>Human & Machine Identity Threat Detection Platform</p>
          </div>
        </div>

        <div className="header-actions">
          <span
            className={`system-status ${
              systemOnline ? "online" : "offline"
            }`}
          >
            <span className="status-dot" />
            {systemOnline ? "System Online" : "System Offline"}
          </span>

          <button
            type="button"
            className="attack-button"
            onClick={simulateAttack}
            disabled={Boolean(loadingAction) || !systemOnline}
          >
            {loadingAction === "attack"
              ? "Simulating..."
              : "Simulate Attack"}
          </button>

          <button
            type="button"
            className="reset-button"
            onClick={resetDemo}
            disabled={Boolean(loadingAction) || !systemOnline}
          >
            {loadingAction === "reset" ? "Resetting..." : "Reset Demo"}
          </button>
        </div>
      </header>

      <nav className="dashboard-nav" aria-label="Dashboard navigation">
        <div className="dashboard-nav-inner">
          {NAV_ITEMS.map((item) => (
            <button
              type="button"
              key={item.id}
              className={`nav-link ${
                activeSection === item.id ? "nav-link-active" : ""
              }`}
              onClick={() => scrollToSection(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </nav>

      <main>
        <section id="overview" className="dashboard-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">COMMAND CENTRE</span>
              <h2>Security Overview</h2>
              <p>Live identity, credential and repository protection status.</p>
            </div>

            <span
              className={`overview-badge ${
                hasHighRisk
                  ? "overview-danger"
                  : hasMediumRisk
                    ? "overview-warning"
                    : "overview-safe"
              }`}
            >
              {hasHighRisk
                ? "⚠ Active Threat"
                : hasMediumRisk
                  ? "⚠ Activity Flagged"
                  : "✓ Environment Secure"}
            </span>
          </div>

          <div className="identity-grid">
            <article className="identity-card">
    <div className="identity-icon">👤</div>

    <div>
      <span className="identity-type">HUMAN IDENTITY</span>
      <h3>Developer Rahul</h3>
      <p>
        Normal baseline: up to 8 repository actions per 10 seconds
      </p>
    </div>

    <span
      className={`identity-status ${
        rahulHighRisk ? "identity-critical" : "identity-normal"
      }`}
    >
      {rahulHighRisk ? "CRITICAL" : "NORMAL"}
    </span>
            </article>

            <article className="identity-card">
    <div className="identity-icon">🤖</div>

    <div>
      <span className="identity-type">MACHINE IDENTITY</span>
      <h3>GitHub AI Agent</h3>
      <p>
        Normal baseline: up to 3 repository actions per 10 seconds
      </p>
    </div>

    <span
      className={`identity-status ${
        agentHighRisk ? "identity-critical" : "identity-normal"
      }`}
    >
      {agentHighRisk ? "CRITICAL" : "NORMAL"}
    </span>
            </article>
          </div>

          <div className="status-grid">
            <article className="status-card">
              <p>Threat Level</p>
              <h2
                className={
                  threatLevel === "HIGH"
                    ? "danger-text"
                    : threatLevel === "MEDIUM"
                      ? "monitoring-text"
                      : "safe-text"
                }
              >
                {threatLevel}
              </h2>
              <small>
                {threatLevel === "HIGH"
                  ? "High-risk identity behaviour detected"
                  : threatLevel === "MEDIUM"
                    ? "Unusual activity flagged for review"
                    : "No malicious activity detected"}
              </small>
            </article>

            <article className="status-card">
              <p>GitHub Credential</p>
              <h2 className={tokenRevoked ? "danger-text" : "safe-text"}>
                {tokenRevoked ? "QUARANTINED" : "ACTIVE"}
              </h2>
              <small>
                {tokenRevoked
                  ? "Credential quarantined"
                  : "Credential under monitoring"}
              </small>
            </article>

            <article className="status-card">
              <p>Requests / 10s</p>
              <h2>{requestCount}</h2>
              <small>Requests observed in the last 10 seconds</small>
            </article>

            <article className="status-card">
              <p>Identity Status</p>
              <h2
                className={
                  tokenRevoked ? "danger-text" : "monitoring-text"
                }
              >
                {tokenRevoked
                ? "BLOCKED"
                : baselineExceeded
                  ? "FLAGGED"
                  : "MONITORING"}
              </h2>
              <small>
                {tokenRevoked
                  ? "Compromised identity blocked"
                  : baselineExceeded
                    ? "Activity flagged without automatic quarantine"
                    : "Human and machine identities monitored"}
              </small>
            </article>
          </div>
        </section>

        <section id="threat" className="chart-panel dashboard-section">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">LIVE DETECTION</span>
              <h2>Live Threat Score</h2>
              <p>
                Hybrid risk calculated from behavioral baselines and Isolation Forest
              </p>
            </div>

            <span
              className={`score-label ${
                threatLevel === "HIGH"
                  ? "score-high"
                  : threatLevel === "MEDIUM"
                    ? "score-medium"
                    : "score-low"
              }`}
            >
              {currentThreatScore}/100
            </span>
          </div>

          {threatData.length === 0 ? (
            <div className="empty-state">
              Threat score will appear when agent activity is detected.
            </div>
          ) : (
            <div className="chart-container">
              <ResponsiveContainer width="100%" height={300}>
                <LineChart
                  data={threatData}
                  margin={{
                    top: 10,
                    right: 20,
                    left: 0,
                    bottom: 5,
                  }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#263653"
                  />

                  <XAxis
                    dataKey="eventNumber"
                    stroke="#8fa7cb"
                    tickLine={false}
                    axisLine={{ stroke: "#304568" }}
                  />

                  <YAxis
                    domain={[0, 100]}
                    stroke="#8fa7cb"
                    tickLine={false}
                    axisLine={{ stroke: "#304568" }}
                  />

                  <Tooltip
                    contentStyle={{
                      background: "#101a2e",
                      border: "1px solid #304568",
                      borderRadius: "10px",
                      color: "#ffffff",
                    }}
                    labelStyle={{ color: "#ffffff" }}
                    formatter={(value) => [
                      `${value}/100`,
                      "Threat Score",
                    ]}
                    labelFormatter={(value) => `Event ${value}`}
                  />

                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke={
                      threatLevel === "HIGH"
                        ? "#ff4d70"
                        : threatLevel === "MEDIUM"
                          ? "#ffb454"
                          : "#42e89b"
                    }
                    strokeWidth={3}
                    dot={{
                      r: 5,
                      fill:
                        threatLevel === "HIGH"
                          ? "#ff4d70"
                          : threatLevel === "MEDIUM"
                            ? "#ffb454"
                            : "#42e89b",
                    }}
                    activeDot={{ r: 7 }}
                    isAnimationActive
                    animationDuration={700}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>
        <section id="baseline" className="baseline-panel dashboard-section">
  <div className="panel-heading">
    <div>
      <span className="section-kicker">BEHAVIORAL COMPARISON</span>
      <h2>Baseline vs Observed Activity</h2>
      <p>
        Comparison between the configured identity baseline and the current
        session.
      </p>
    </div>

    <span
      className={`decision-badge ${
        mlIsAnomaly
          ? "decision-blocked"
          : "decision-monitoring"
      }`}
    >
      {mlIsAnomaly
        ? "ML ANOMALY DETECTED"
        : baselineExceeded
          ? "BASELINE EXCEEDED"
          : "WITHIN BASELINE"}
    </span>
  </div>

  <div className="baseline-grid">
    <article className="baseline-card">
      <span>Monitored Identity</span>
      <strong>{activeIncidentEvent?.agent || "No activity"}</strong>
    </article>

    <article className="baseline-card">
      <span>Identity Type</span>
      <strong>{activeIncidentEvent?.entityType || "UNKNOWN"}</strong>
    </article>

    <article className="baseline-card">
      <span>Expected Activity</span>
      <strong>Up to {currentThreshold} requests</strong>
    </article>

    <article className="baseline-card">
      <span>Observed Activity</span>
      <strong>{requestCount} requests</strong>
    </article>

    <article className="baseline-card">
      <span>Deviation</span>
      <strong>
        {Math.max(0, requestCount - currentThreshold)} requests above baseline
      </strong>
    </article>

    <article className="baseline-card">
      <span>Decision</span>
      <strong
        className={
          mlIsAnomaly
            ? "danger-text"
            : baselineExceeded
              ? "monitoring-text"
              : "safe-text"
        }
      >
        {mlIsAnomaly
          ? "SUSPICIOUS"
          : baselineExceeded
            ? "FLAGGED"
            : "NORMAL"}
      </strong>
    </article>

    <article className="baseline-card">
      <span>Detection Method</span>
      <strong>Hybrid baseline + ML detection</strong>
    </article>

    <article className="baseline-card">
      <span>ML Model</span>
      <strong>{mlModel}</strong>
    </article>

    <article className="baseline-card">
      <span>ML Prediction</span>
      <strong className={mlIsAnomaly ? "danger-text" : "safe-text"}>
        {mlAvailable ? mlPrediction : "UNAVAILABLE"}
      </strong>
    </article>

    <article className="baseline-card">
      <span>Activity Explanation</span>
      <strong
        className={
          !mlAvailable
            ? "monitoring-text"
            : mlIsAnomaly
              ? "danger-text"
              : "safe-text"
        }
      >
        {activityExplanation}
      </strong>
      <small>{activityDetails}</small>
    </article>

    <article className="baseline-card">
      <span>ML Anomaly Score</span>
      <strong>{mlAnomalyScore.toFixed(2)}/100</strong>
    </article>

    <article className="baseline-card">
      <span>Hybrid Risk Score</span>
      <strong
        className={
          hybridRiskScore >= 70
            ? "danger-text"
            : hybridRiskScore >= 40
              ? "monitoring-text"
              : "safe-text"
        }
      >
        {hybridRiskScore}/100
      </strong>
    </article>
  </div>
</section>

        <section
          id="repository"
          className="repository-panel dashboard-section"
        >
          <div className="panel-heading">
            <div>
              <span className="section-kicker">ACCESS CONTROL</span>
              <h2>Protected GitHub Repository</h2>
              <p>
                Verify whether a monitored identity can access the protected
                private repository
              </p>
            </div>

            <div className="repository-action">
              <button
                type="button"
                className="repository-button"
                onClick={fetchRepositoryFiles}
                disabled={repositoryLoading || !systemOnline}
              >
                {repositoryLoading
                  ? "Checking Access..."
                  : tokenRevoked
                    ? "Retry as Flagged Identity"
                    : "Test Repository Access"}
              </button>

              <small className="repository-action-caption">
                {tokenRevoked
                  ? "Simulates the flagged identity attempting the same repository action again."
                  : "Tests whether the monitored identity can currently access the repository."}
              </small>
            </div>
          </div>

          <div className={`repository-status ${repositoryPanelState}`}>
            <strong>
              {repositoryAccessState === "blocked" || tokenRevoked
                ? "Access Protection Active"
                : repositoryAccessState === "allowed"
                  ? "Repository Access Allowed"
                  : "Repository Access Unchecked"}
            </strong>

            <span>{repositoryMessage}</span>
          </div>

          {repositoryFiles.length > 0 && (
            <div className="repository-file-grid">
              {repositoryFiles.map((file, index) => (
                <article
  className="repository-file"
  key={
    file.sha ||
    file.path ||
    file.name ||
    `repository-file-${index}`
  }
  role="button"
  tabIndex={0}
  title={`Open ${file.name || file.path || "repository file"}`}
  onClick={() => {
    const fileUrl = file.html_url || file.download_url;

    if (fileUrl) {
      window.open(fileUrl, "_blank", "noopener,noreferrer");
    }
  }}
  onKeyDown={(event) => {
    if (event.key === "Enter" || event.key === " ") {
      const fileUrl = file.html_url || file.download_url;

      if (fileUrl) {
        window.open(fileUrl, "_blank", "noopener,noreferrer");
      }
    }
  }}
>
                  <span className="file-icon">
                    {file.type === "dir" ? "📁" : "📄"}
                  </span>

                  <div>
                    <strong>
                      {file.name || file.path || "Unknown file"}
                    </strong>
                    <p>{file.type || "file"}</p>
                  </div>
                </article>
              ))}
            </div>
          )}

          {(repositoryAccessState === "blocked" || tokenRevoked) && (
            <div className="access-denied-box">
              <span className="access-denied-code">401</span>

              <div>
                <h3>Repository Access Denied</h3>
                <p>
                  The compromised identity can no longer access the protected
                  repository through ShadowGuard.
                </p>
              </div>
            </div>
          )}
        </section>

        <section id="analysis" className="dashboard-section">
          <section className="attack-path-panel">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">ATTACK ANALYSIS</span>
                <h2>Attack Path & Containment</h2>
                <p>
                  Visual trace of how the compromised identity attempted to reach protected GitHub assets
                </p>
              </div>

              <span
                className={`containment-badge ${
                  tokenRevoked ? "contained" : "monitoring"
                }`}
              >
                {tokenRevoked ? "CONTAINED" : "MONITORING"}
              </span>
            </div>

            <div className="attack-path-grid">
              {[
                [
                  activeIncidentEvent?.entityType === "HUMAN" ? "👤" : "🤖",
                  activeIncidentEvent?.agent || "Monitored Identity",
                  tokenRevoked ? "Identity blocked" : "Activity monitored",
                ],
                ["🔑", "GitHub Token", tokenRevoked ? "Credential quarantined" : "Credential active"],
                ["📦", "Private Repository", tokenRevoked ? "Access denied" : "Protected asset reachable"],
                ["📄", "Sensitive Files", tokenRevoked ? "Exfiltration prevented" : "Files monitored"],
              ].map((node, index) => (
                <div className="attack-path-fragment" key={node[1]}>
                  <div className="attack-node">
                    <span className="attack-icon">{node[0]}</span>
                    <h3>{node[1]}</h3>
                    <p>{node[2]}</p>
                  </div>

                  {index < 3 && (
                    <div
                      className={`path-arrow ${
                        tokenRevoked ? "blocked-arrow" : ""
                      }`}
                    >
                      →
                    </div>
                  )}
                </div>
              ))}
            </div>

            <div
              className={`containment-strip ${
                tokenRevoked ? "active" : ""
              }`}
            >
              <div>
                <strong>ShadowGuard AI</strong>
                <span>
                  {tokenRevoked
                    ? "Threat detected → credential quarantined → repository access blocked"
                    : "Monitoring identity behavior and repository access velocity"}
                </span>
              </div>

              <span className="containment-status">
                {tokenRevoked ? "Attack Contained" : "No Active Threat"}
              </span>
            </div>
          </section>

          <section className="mitre-panel">
            <div className="panel-heading">
              <div>
                <h2>MITRE ATT&CK Mapping</h2>
                <p>
                  Security techniques associated with the detected GitHub
                  identity abuse
                </p>
              </div>

              <span
                className={`mitre-status ${
                  tokenRevoked ? "mitre-detected" : "mitre-monitoring"
                }`}
              >
                {tokenRevoked ? "DETECTED" : "MONITORING"}
              </span>
            </div>

            <div className="mitre-grid">
              {[
                ["T1078", "Valid Accounts", "A valid GitHub credential was used by a potentially compromised AI identity.", tokenRevoked],
                ["T1083", "File and Directory Discovery", "The agent accessed repository contents and attempted to discover files.", events.length > 0],
                ["T1552", "Unsecured Credentials", "The GitHub Personal Access Token represented the credential at risk.", tokenRevoked],
              ].map(([id, title, text, detected]) => (
                <article className="mitre-card" key={id}>
                  <div className="mitre-card-header">
                    <span className="mitre-check">{detected ? "✓" : "•"}</span>
                    <div>
                      <span className="mitre-id">{id}</span>
                      <h3>{title}</h3>
                    </div>
                  </div>
                  <p>{text}</p>
                  <span
                    className={`technique-state ${
                      detected ? "technique-detected" : ""
                    }`}
                  >
                    {detected ? "Technique observed" : "Monitoring"}
                  </span>
                </article>
              ))}
            </div>

            <div className="mitre-summary">
              <div>
  <span>Decision Conditions</span>
  <strong>{decisionConditionValue} Met</strong>
</div>
              <div>
                <span>Mapped Techniques</span>
                <strong>
                  {tokenRevoked ? "3" : events.length > 0 ? "1" : "0"}
                </strong>
              </div>
              <div>
                <span>Response Status</span>
                <strong className={tokenRevoked ? "safe-text" : "monitoring-text"}>
                  {tokenRevoked ? "CONTAINED" : "MONITORING"}
                </strong>
              </div>
            </div>
          </section>

          <section className="explainability-panel">
            <div className="panel-heading">
              <div>
                <h2>
                  {tokenRevoked
                    ? "Why Was This Blocked?"
                    : baselineExceeded
                      ? "Why Was This Flagged?"
                      : "How Is This Activity Evaluated?"}
                </h2>
                <p>
                  Explainable decision based on the identity’s behavioral activity.
                </p>
              </div>

              <span
                className={`decision-badge ${
                  tokenRevoked
                    ? "decision-blocked"
                    : "decision-monitoring"
                }`}
              >
                {tokenRevoked
                  ? "BLOCKED"
                  : baselineExceeded || threatLevel === "MEDIUM"
                    ? "FLAGGED"
                    : "MONITORING"}
              </span>
            </div>

            <div className="explainability-grid">
              <div className="reason-list">
                {[
                  ["Repository read velocity exceeded", "The identity generated repeated repository requests within the monitoring window.", baselineExceeded],
                  [`${requestCount} requests vs baseline ${currentThreshold}`, "The activity exceeded the configured behavioral threshold.", baselineExceeded],
                  [
                    `Isolation Forest prediction: ${mlPrediction}`,
                    `The trained model produced an anomaly score of ${mlAnomalyScore.toFixed(2)}/100.`,
                    mlIsAnomaly,
                  ],
                  [
                    "Behavioral baseline violated",
                    "The observed access pattern no longer matched the identity baseline.",
                    baselineExceeded,
                  ],
                  [
                    "Credential containment required",
                    "The suspicious identity retained access to a protected credential.",
                    tokenRevoked,
                  ],
                ].map(([title, text, active]) => (
                  <article
                    className={`reason-item ${
                      active ? "reason-triggered" : ""
                    }`}
                    key={title}
                  >
                    <span className="reason-icon">{active ? "✓" : "•"}</span>
                    <div>
                      <h3>{title}</h3>
                      <p>{text}</p>
                    </div>
                  </article>
                ))}
              </div>

              <aside className="decision-panel">
                <div className="decision-score">
                  <span>Risk Score</span>
                  <strong>{currentThreatScore}/100</strong>
                </div>

                <div className="decision-progress">
                  <div
                    className={`decision-progress-fill ${
                      tokenRevoked ? "progress-danger" : "progress-safe"
                    }`}
                    style={{ width: `${currentThreatScore}%` }}
                  />
                </div>

                <div className="decision-details">
                  <div>
                    <span>Decision</span>
                    <strong
                      className={
                        tokenRevoked
                          ? "danger-text"
                          : baselineExceeded
                            ? "monitoring-text"
                            : "safe-text"
                      }
                    >
                      {tokenRevoked
                        ? "HIGH RISK"
                        : baselineExceeded
                          ? "FLAGGED"
                          : "NORMAL"}
                    </strong>
                  </div>

                  <div>
                    <span>Action Taken</span>
                    <strong>
                      {tokenRevoked
                        ? "Credential Quarantined"
                        : baselineExceeded
                          ? "Alert Generated"
                          : "No Action Required"}
                    </strong>
                  </div>

                  <div>
                    <span>Repository</span>
                    <strong
                      className={
                        tokenRevoked ? "safe-text" : "monitoring-text"
                      }
                    >
                      {tokenRevoked ? "PROTECTED" : "MONITORED"}
                    </strong>
                  </div>

                  <div>
                    <span>Containment</span>
                    <strong
                      className={
                        tokenRevoked
                          ? "safe-text"
                          : baselineExceeded
                            ? "monitoring-text"
                            : "safe-text"
                      }
                    >
                      {tokenRevoked
                        ? "SUCCESSFUL"
                        : baselineExceeded
                          ? "AWAITING POLICY"
                          : "NOT REQUIRED"}
                    </strong>
                  </div>
                </div>
              </aside>
            </div>
          </section>

          <section className="analytics-panel">
            <div className="panel-heading">
              <div>
                <h2>Security Analytics</h2>
                <p>Real-time operational metrics generated by ShadowGuard AI</p>
              </div>

              <span className="analytics-live">
                <span className="analytics-live-dot" />
                LIVE
              </span>
            </div>

            <div className="analytics-grid">
              {[
                ["🛡️", protectedAssetCount, "Protected Assets", "Private Repository"],
                ["📊", events.length, "Events Processed", "Live Detection"],
                [
                  "🧠",
                  mlAvailable ? mlPrediction : "UNAVAILABLE",
                  "ML Prediction",
                  mlModel,
                ],
                [
                  "📈",
                  `${mlAnomalyScore.toFixed(2)}/100`,
                  "ML Anomaly Score",
                  "Isolation Forest output",
                ],
                [
                  "🎯",
                  `${hybridRiskScore}/100`,
                  "Hybrid Risk Score",
                  "Baseline + ML + asset sensitivity",
                ],
                [
                  "⚡",
                  tokenRevoked ? "AUTOMATED" : "STANDBY",
                  "Response Mode",
                  "Policy-based containment",
                ],
                [
                  "✅",
                  decisionConditionValue,
                  "Conditions Met",
                  "Explainable decision logic",
                ],
              ].map(([icon, value, label, note]) => (
                <article className="analytics-card" key={label}>
                  <div className="analytics-icon">{icon}</div>
                  <h3>{value}</h3>
                  <span>{label}</span>
                  <small>{note}</small>
                </article>
              ))}
            </div>
          </section>
        </section>

        <section id="timeline" className="timeline-panel dashboard-section">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">INCIDENT RECONSTRUCTION</span>
              <h2>Attack Timeline</h2>
              <p>
                Chronological view of detection, response, and containment activity
              </p>
            </div>

            <span
              className={`timeline-status ${
                tokenRevoked ? "timeline-contained" : "timeline-monitoring"
              }`}
            >
              {tokenRevoked ? "CONTAINED" : "MONITORING"}
            </span>
          </div>

          <div className="timeline-list">
            {[
              ["Identity Activity Started", "A monitored identity began accessing the protected repository.", events.length > 0, events[0]?.time || "Waiting", "complete"],
              ["Repository File Accessed", "Repository contents were requested using the GitHub Personal Access Token.", events.length > 0, events[0]?.time || "Pending", "complete"],
              [
  "Request Velocity Increased",
  "Repeated repository requests were observed inside the monitoring window.",
  requestCount >= currentThreshold,
  requestCount >= currentThreshold
    ? `${requestCount} requests`
    : "Pending",
  "warning",
],
             [
  "Behavioral Threshold Exceeded",
  `Observed ${requestCount} requests against a baseline of ${currentThreshold}.`,
  baselineExceeded,
  baselineExceeded ? "Detected" : "Pending",
  "danger",
],
              ["Threat Score Escalated", "The behavioral risk engine classified the activity as high risk.", hasHighRisk, hasHighRisk ? `${currentThreatScore}/100` : "Pending", "danger"],
             [
  "Credential Quarantined",
  "ShadowGuard AI disabled the compromised credential inside its access-control layer.",
  tokenRevoked,
  tokenRevoked ? "Completed" : "Pending",
  "danger",
],
              ["Repository Access Blocked", "The compromised agent could no longer reach the private repository.", repositoryAccessState === "blocked" || tokenRevoked, repositoryAccessState === "blocked" || tokenRevoked ? "401 Unauthorized" : "Pending", "complete"],
              ["Attack Contained", "Credential misuse was stopped and the protected asset remained secure.", tokenRevoked, tokenRevoked ? "Successful" : "Pending", "contained"],
            ].map(([title, text, active, meta, state], index) => (
              <article
                className={`timeline-item ${
                  active ? `timeline-${state}` : ""
                }`}
                key={title}
              >
                <span className="timeline-marker">{index + 1}</span>

                <div className="timeline-content">
                  <div className="timeline-meta">
                    <h3>{title}</h3>
                    <span>{meta}</span>
                  </div>
                  <p>{text}</p>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section id="architecture" className="dashboard-section">
          <button
            type="button"
            className="architecture-toggle"
            onClick={() => setArchitectureOpen((open) => !open)}
            aria-expanded={architectureOpen}
          >
            <div>
              <span className="section-kicker">TECHNICAL DETAILS</span>
              <h2>ShadowGuard AI Architecture</h2>
              <p>
                View the end-to-end detection, risk analysis, and containment workflow.
              </p>
            </div>

            <span className="architecture-toggle-label">
              {architectureOpen ? "Collapse ▲" : "Expand ▼"}
            </span>
          </button>

          {architectureOpen && (
            <section className="architecture-panel architecture-expanded">
              <div className="panel-heading">
                <div>
                  <h2>End-to-End Security Workflow</h2>
                  <p>
                    From AI agent activity to automated containment
                  </p>
                </div>

                <span
                  className={`architecture-status ${
                    tokenRevoked
                      ? "architecture-protected"
                      : "architecture-monitoring"
                  }`}
                >
                  {tokenRevoked ? "PROTECTED" : "MONITORING"}
                </span>
              </div>

              <div className="architecture-flow">
                {[
                  ["🤖", "AI Agent", "Accesses GitHub resources using an assigned identity."],
                  ["🔑", "GitHub PAT", "Provides controlled access to the private repository."],
                  ["📡", "Activity Collector", "Logs repository access and identity behavior in real time."],
                  ["🧠", "Behavior Engine", "Compares request velocity against the behavioral baseline."],
                  ["🎯", "Hybrid Risk Engine", "Combines baseline deviation, Isolation Forest output, and asset sensitivity."],
                  ["⚡", "Response Engine", "Quarantines the credential when the hybrid risk score reaches HIGH."],
                  ["🛡️", "Repository Protected", tokenRevoked ? "Compromised access is blocked and the attack is contained." : "Repository access remains under continuous monitoring."],
                ].map(([icon, title, text], index) => (
                  <div className="architecture-fragment" key={title}>
                    <article
                      className={`architecture-node ${
                        title === "Hybrid Risk Engine" && hasHighRisk
                          ? "architecture-alert-node"
                          : ""
                      } ${
                        title === "Response Engine" && tokenRevoked
                          ? "architecture-response-node"
                          : ""
                      } ${
                        title === "Repository Protected" && tokenRevoked
                          ? "architecture-protected-node"
                          : ""
                      }`}
                    >
                      <span className="architecture-icon">{icon}</span>
                      <h3>{title}</h3>
                      <p>{text}</p>
                    </article>

                    {index < 6 && <div className="architecture-arrow">→</div>}
                  </div>
                ))}
              </div>

              <div className="architecture-summary">
                <div>
                  <span>Detection Layer</span>
                  <strong>Baseline + Isolation Forest</strong>
                </div>
                <div>
                  <span>Decision Layer</span>
                  <strong>{currentThreatScore}/100 Risk Score</strong>
                </div>
                <div>
                  <span>Response Layer</span>
                  <strong>{tokenRevoked ? "Credential Quarantine" : "Standby"}</strong>
                </div>
                <div>
                  <span>Final State</span>
                  <strong className={tokenRevoked ? "safe-text" : "monitoring-text"}>
                    {tokenRevoked ? "ATTACK CONTAINED" : "MONITORING"}
                  </strong>
                </div>
              </div>
            </section>
          )}
        </section>

        <section id="events" className="events-panel dashboard-section">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">SECURITY TELEMETRY</span>
              <h2>Live Security Events</h2>
              <p>Live activity from monitored human and machine identities</p>
            </div>

            <button
              type="button"
              className="refresh-button"
              onClick={fetchEvents}
              disabled={!systemOnline}
            >
              Refresh
            </button>
          </div>

          {events.length === 0 ? (
            <div className="empty-state">No identity activity detected yet.</div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Identity</th>
                    <th>Identity Type</th>
                    <th>Action</th>
                    <th>Requests / 10s</th>
                    <th>ML Result</th>
                    <th>ML Score</th>
                    <th>Hybrid Score</th>
                    <th>Risk</th>
                  </tr>
                </thead>

                <tbody>
                  {[...events].reverse().map((event, index) => (
                    <tr key={event.id || `${event.time}-${index}`}>
                      <td>{event.time || "-"}</td>
                      <td>{event.agent || "Unknown Identity"}</td>
                      <td>{event.entityType || "UNKNOWN"}</td>
                      <td>{event.action || "Unknown Action"}</td>
                      <td>{event.requestCount || 0}</td>
                      <td>
                        <span
                          className={`risk-badge ${
                            event.mlIsAnomaly ? "risk-high" : "risk-low"
                          }`}
                        >
                          {event.mlPrediction || "NO DATA"}
                        </span>
                      </td>
                      <td>
                        {Number(event.mlAnomalyScore || 0).toFixed(2)}
                      </td>
                      <td>
                        {Number(event.combinedRiskScore || 0)}/100
                      </td>
                      <td>
                        <span
                          className={`risk-badge ${
  event.risk === "HIGH"
    ? "risk-high"
    : event.risk === "MEDIUM"
      ? "risk-medium"
      : "risk-low"
}`}
                        >
                          {event.risk || "LOW"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {tokenRevoked && (
          <section className="response-panel">
            <h2>Automated Response Triggered</h2>
            <p>
              ShadowGuard combined baseline deviation with ML anomaly detection and
              quarantined the credential to stop further access.
            </p>

            <div className="response-details">
              <span>Detection: Hybrid baseline + Isolation Forest</span>
              <span>Response: Credential quarantined</span>
              <span>Identity: {compromisedIdentity || "Unknown"} blocked</span>
            </div>
          </section>
        )}
      </main>

      <footer className="dashboard-footer">
        <strong>ShadowGuard AI</strong>
        <span>React • Node.js • Flask • Isolation Forest • GitHub API • MITRE ATT&CK</span>
      </footer>
    </div>
  );
}

export default App;