const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { getRepositoryFiles } = require("./github");
const {
  checkThreat,
  resetThreatDetector,
} = require("./detector");
const {
  revokeToken,
  isTokenRevoked,
  resetToken,
} = require("./revoke");

const app = express();
const PORT = Number(process.env.PORT) || 5000;

const ML_SERVICE_URL =
  process.env.ML_SERVICE_URL || "http://127.0.0.1:5001";

const USE_ML =
  String(process.env.USE_ML ?? "true").toLowerCase() !== "false";

const ML_TIMEOUT_MS =
  Number(process.env.ML_TIMEOUT_MS) || 2000;

app.use(cors());
app.use(express.json());

let events = [];

function toNonNegativeNumber(value, fallback = 0) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }

  return parsed;
}

function buildFeatures({
  requestCount,
  entityType,
  uniqueFiles = 1,
  failedRequests = 0,
  sensitiveFileAccesses = 0,
}) {
  return {
    requests10s: toNonNegativeNumber(requestCount),
    uniqueFiles: toNonNegativeNumber(uniqueFiles, 1),
    failedRequests: toNonNegativeNumber(failedRequests),
    sensitiveFileAccesses: toNonNegativeNumber(
      sensitiveFileAccesses
    ),
    identityType:
      String(entityType || "MACHINE").toUpperCase() === "HUMAN"
        ? "HUMAN"
        : "MACHINE",
  };
}

async function getMlPrediction(features) {
  if (!USE_ML) {
    return {
      available: false,
      isAnomaly: false,
      prediction: "DISABLED",
      anomalyScore: 0,
      decisionScore: null,
      model: "Isolation Forest",
      error: "ML integration disabled by configuration",
    };
  }

  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();

    const timeout = setTimeout(
      () => controller.abort(),
      ML_TIMEOUT_MS
    );

    try {
      const response = await fetch(
        `${ML_SERVICE_URL}/predict`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(features),
          signal: controller.signal,
        }
      );

      const responseText = await response.text();

      let data;

      try {
        data = JSON.parse(responseText);
      } catch {
        throw new Error(
          `ML service returned non-JSON response: ${response.status} ${responseText.slice(0, 80)}`
        );
      }

      if (!response.ok) {
        throw new Error(
          data.error || `ML service returned ${response.status}`
        );
      }

      return {
        available: true,
        isAnomaly: Boolean(data.isAnomaly),
        prediction: data.prediction || "UNKNOWN",
        anomalyScore: toNonNegativeNumber(data.anomalyScore),
        decisionScore:
          data.decisionScore === null ||
          data.decisionScore === undefined
            ? null
            : Number(data.decisionScore),
        model: data.model || "Isolation Forest",
        error: null,
      };
    } catch (error) {
      const message =
        error.name === "AbortError"
          ? "ML request timed out"
          : error.message;

      console.error(
        `ML prediction attempt ${attempt}/${maxAttempts} failed:`,
        message
      );

      if (attempt < maxAttempts) {
        await new Promise((resolve) =>
          setTimeout(resolve, attempt * 2000)
        );
      } else {
        return {
          available: false,
          isAnomaly: false,
          prediction: "UNAVAILABLE",
          anomalyScore: 0,
          decisionScore: null,
          model: "Isolation Forest",
          error: message,
        };
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

function calculateHybridRisk({
  baselineExceeded,
  mlIsAnomaly,
  sensitiveFileAccesses,
}) {
  // Hybrid scoring policy:
  // - Baseline exceeded: 50 points
  // - ML anomaly: 50 points
  // - Sensitive-file access: 20 points
  //
  // This allows an ML anomaly involving sensitive files
  // to reach HIGH risk even before the request baseline
  // is exceeded: 50 + 20 = 70.
  const baselinePoints = baselineExceeded ? 50 : 0;
  const mlPoints = mlIsAnomaly ? 50 : 0;
  const sensitiveAssetPoints =
    Number(sensitiveFileAccesses) > 0 ? 20 : 0;

  const score = Math.min(
    100,
    baselinePoints + mlPoints + sensitiveAssetPoints
  );

  let risk = "LOW";

  if (score >= 70) {
    risk = "HIGH";
  } else if (score >= 40) {
    risk = "MEDIUM";
  }

  return {
    score,
    risk,
    breakdown: {
      baselinePoints,
      mlPoints,
      sensitiveAssetPoints,
    },
  };
}

async function buildSecurityEvent({
  id,
  agent,
  action,
  result,
  uniqueFiles,
  failedRequests,
  sensitiveFileAccesses,
}) {
  const entityType =
    result.baseline?.entityType || "UNKNOWN";

  const features = buildFeatures({
    requestCount: result.count,
    entityType,
    uniqueFiles,
    failedRequests,
    sensitiveFileAccesses,
  });

  const ml = await getMlPrediction(features);

  const hybridRisk = calculateHybridRisk({
    baselineExceeded: result.suspicious,
    mlIsAnomaly: ml.available && ml.isAnomaly,
    sensitiveFileAccesses:
      features.sensitiveFileAccesses,
  });

  return {
    id,
    time: new Date().toLocaleTimeString(),
    timestamp: new Date().toISOString(),
    agent,
    action,

    risk: hybridRisk.risk,
    combinedRiskScore: hybridRisk.score,
    riskBreakdown: hybridRisk.breakdown,

    requestCount: result.count,
    threshold: result.threshold,
    baselineExceeded: result.suspicious,
    entityType,

    mlAvailable: ml.available,
    mlPrediction: ml.prediction,
    mlIsAnomaly: ml.available && ml.isAnomaly,
    mlAnomalyScore: ml.anomalyScore,
    mlDecisionScore: ml.decisionScore,
    mlModel: ml.model,
    mlError: ml.error,

    features,
  };
}

// Home route
app.get("/", (req, res) => {
  res.json({
    status: "online",
    service: "ShadowGuard AI Backend",
    mlEnabled: USE_ML,
    mlServiceUrl: ML_SERVICE_URL,
  });
});

// Get repository files
app.get("/files", async (req, res) => {
  if (isTokenRevoked()) {
    return res.status(401).json({
      error:
        "Credential quarantined by ShadowGuard AI access-control layer",
    });
  }

  try {
    const files = await getRepositoryFiles();
    return res.json(files);
  } catch (error) {
    console.error(
      "Failed to fetch repository files:",
      error.response?.data || error.message
    );

    return res
      .status(error.response?.status || 500)
      .json({
        error: "Failed to fetch files",
      });
  }
});

// Log monitored identity activity
app.post("/log", async (req, res) => {
  try {
    const agent =
      req.body.agent || "Unknown Agent";
    const action =
      req.body.action || "Unknown Action";

    const result = checkThreat(agent);

    const event = await buildSecurityEvent({
      id: Date.now(),
      agent,
      action,
      result,
      uniqueFiles: req.body.uniqueFiles ?? 1,
      failedRequests:
        req.body.failedRequests ?? 0,
      sensitiveFileAccesses:
        req.body.sensitiveFileAccesses ?? 0,
    });

    if (
      event.risk === "HIGH" &&
      !isTokenRevoked()
    ) {
      revokeToken();
    }

    events.push(event);
    console.log(event);

    return res.json({
      status: event.risk,
      combinedRiskScore:
        event.combinedRiskScore,
      requests: event.requestCount,
      threshold: event.threshold,
      baselineExceeded:
        event.baselineExceeded,
      entityType: event.entityType,
      mlAvailable: event.mlAvailable,
      mlPrediction: event.mlPrediction,
      mlIsAnomaly: event.mlIsAnomaly,
      mlAnomalyScore:
        event.mlAnomalyScore,
      riskBreakdown:
        event.riskBreakdown,
      features:
        event.features,
      tokenRevoked: isTokenRevoked(),
    });
  } catch (error) {
    console.error(
      "Failed to process security event:",
      error.message
    );

    return res.status(500).json({
      error: "Failed to process security event",
    });
  }
});

// Simulate rapid malicious activity
app.post(
  "/simulate-attack",
  async (req, res) => {
    try {
      const generatedEvents = [];
      const agent = "GitHub AI Agent";

      for (let i = 1; i <= 7; i++) {
        const result = checkThreat(agent);

        const event =
          await buildSecurityEvent({
            id: Date.now() + i,
            agent,
            action: `Rapid repository read ${i}`,
            result,

            // Synthetic attack features used by
            // the trained Isolation Forest.
            uniqueFiles: Math.min(9, i + 3),
            failedRequests:
              i >= 3 ? Math.min(4, i - 1) : 1,
            sensitiveFileAccesses:
              i >= 2 ? Math.min(3, i - 1) : 1,
          });

        if (
          event.risk === "HIGH" &&
          !isTokenRevoked()
        ) {
          revokeToken();
        }

        events.push(event);
        generatedEvents.push(event);
        console.log(event);
      }

      return res.json({
        message:
          "Hybrid ML attack simulation completed",
        tokenRevoked: isTokenRevoked(),
        generatedEvents,
      });
    } catch (error) {
      console.error(
        "Attack simulation failed:",
        error.message
      );

      return res.status(500).json({
        error: "Attack simulation failed",
      });
    }
  }
);

// Get all events
app.get("/events", (req, res) => {
  return res.json(events);
});

// Get current system status
app.get("/status", (req, res) => {
  const latestEvent =
    events.length > 0
      ? events[events.length - 1]
      : null;

  return res.json({
    backendOnline: true,
    mlEnabled: USE_ML,
    tokenRevoked: isTokenRevoked(),
    threatLevel: latestEvent?.risk || "LOW",
    combinedRiskScore:
      latestEvent?.combinedRiskScore || 0,
    mlPrediction:
      latestEvent?.mlPrediction || "NO DATA",
    mlAnomalyScore:
      latestEvent?.mlAnomalyScore || 0,
    totalEvents: events.length,
    latestEvent,
  });
});

// Reset demo state
app.post("/reset", (req, res) => {
  events = [];

  resetThreatDetector();

  if (typeof resetToken === "function") {
    resetToken();
  }

  return res.json({
    message:
      "ShadowGuard AI demo reset successfully",
    tokenRevoked: isTokenRevoked(),
    events: [],
  });
});

// Handle unknown routes
app.use((req, res) => {
  return res.status(404).json({
    error: "Route not found",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(
    `🚀 Server running on http://localhost:${PORT}`
  );
  console.log(
    `🧠 ML integration: ${
      USE_ML ? "enabled" : "disabled"
    }`
  );
  console.log(
    `🔗 ML service: ${ML_SERVICE_URL}`
  );
});
