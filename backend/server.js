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
  process.env.ML_SERVICE_URL ||
  "http://127.0.0.1:5001";

const USE_ML =
  String(process.env.USE_ML ?? "true").toLowerCase() !==
  "false";

// Keep ML timeout short so baseline detection is not delayed.
const ML_TIMEOUT_MS =
  Number(process.env.ML_TIMEOUT_MS) || 1500;

app.use(cors());
app.use(express.json());

let events = [];

/**
 * Convert values safely into non-negative numbers.
 */
function toNonNegativeNumber(value, fallback = 0) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }

  return parsed;
}

/**
 * Build feature data for the ML service.
 */
function buildFeatures({
  requestCount,
  entityType,
  uniqueFiles = 1,
  failedRequests = 0,
  sensitiveFileAccesses = 0,
}) {
  return {
    requests10s: toNonNegativeNumber(requestCount),

    uniqueFiles: toNonNegativeNumber(
      uniqueFiles,
      1
    ),

    failedRequests:
      toNonNegativeNumber(failedRequests),

    sensitiveFileAccesses:
      toNonNegativeNumber(
        sensitiveFileAccesses
      ),

    identityType:
      String(entityType || "MACHINE").toUpperCase() ===
      "HUMAN"
        ? "HUMAN"
        : "MACHINE",
  };
}

/**
 * Get anomaly prediction from the ML service.
 *
 * Important:
 * Only one attempt is made. If the ML service is down,
 * ShadowGuard immediately falls back to baseline detection.
 */
async function getMlPrediction(features) {
  if (!USE_ML) {
    return {
      available: false,
      isAnomaly: false,
      prediction: "DISABLED",
      anomalyScore: 0,
      decisionScore: null,
      model: "Isolation Forest",
      error:
        "ML integration disabled by configuration",
    };
  }

  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, ML_TIMEOUT_MS);

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
        `ML service returned non-JSON response: ${
          response.status
        } ${responseText.slice(0, 80)}`
      );
    }

    if (!response.ok) {
      throw new Error(
        data.error ||
          `ML service returned ${response.status}`
      );
    }

    return {
      available: true,

      isAnomaly: Boolean(data.isAnomaly),

      prediction:
        data.prediction || "UNKNOWN",

      anomalyScore:
        toNonNegativeNumber(data.anomalyScore),

      decisionScore:
        data.decisionScore === null ||
        data.decisionScore === undefined
          ? null
          : Number(data.decisionScore),

      model:
        data.model || "Isolation Forest",

      error: null,
    };
  } catch (error) {
    const message =
      error.name === "AbortError"
        ? `ML request timed out after ${ML_TIMEOUT_MS}ms`
        : error.message;

    console.error(
      "ML prediction unavailable. Continuing with baseline detection:",
      message
    );

    return {
      available: false,
      isAnomaly: false,
      prediction: "UNAVAILABLE",
      anomalyScore: 0,
      decisionScore: null,
      model: "Isolation Forest",
      error: message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Calculate the final hybrid risk score.
 */
function calculateHybridRisk({
  baselineExceeded,
  mlIsAnomaly,
  sensitiveFileAccesses,
}) {
  const baselinePoints =
    baselineExceeded ? 50 : 0;

  const mlPoints =
    mlIsAnomaly ? 50 : 0;

  const sensitiveAssetPoints =
  Number(sensitiveFileAccesses) > 0
    ? 70
    : 0;

  const score = Math.min(
    100,
    baselinePoints +
      mlPoints +
      sensitiveAssetPoints
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

/**
 * Build the complete event shown on the dashboard.
 */
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

    mlIsAnomaly:
      ml.available && ml.isAnomaly,

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

    combinedRiskScore:
      hybridRisk.score,

    riskBreakdown:
      hybridRisk.breakdown,

    requestCount:
      result.count,

    threshold:
      result.threshold,

    baselineExceeded:
      result.suspicious,

    entityType,

    mlAvailable:
      ml.available,

    mlPrediction:
      ml.prediction,

    mlIsAnomaly:
      ml.available && ml.isAnomaly,

    mlAnomalyScore:
      ml.anomalyScore,

    mlDecisionScore:
      ml.decisionScore,

    mlModel:
      ml.model,

    mlError:
      ml.error,

    features,
  };
}

/**
 * Health-check route.
 */
app.get("/", (req, res) => {
  return res.json({
    status: "online",

    service:
      "ShadowGuard AI Backend",

    mlEnabled:
      USE_ML,

    mlServiceUrl:
      ML_SERVICE_URL,

    mlTimeoutMs:
      ML_TIMEOUT_MS,
  });
});

/**
 * Read repository files.
 */
app.get("/files", async (req, res) => {
  if (isTokenRevoked()) {
    return res.status(401).json({
      error:
        "Credential quarantined by ShadowGuard AI access-control layer",
    });
  }

  try {
    const files =
      await getRepositoryFiles();

    return res.json(files);
  } catch (error) {
    console.error(
      "Failed to fetch repository files:",
      error.response?.data ||
        error.message
    );

    return res
      .status(
        error.response?.status || 500
      )
      .json({
        error:
          "Failed to fetch files",
      });
  }
});

/**
 * Receive monitored identity activity.
 */
app.post("/log", async (req, res) => {
  try {
    const agent =
      req.body.agent ||
      "Unknown Agent";

    const action =
      req.body.action ||
      "Unknown Action";

    // Count the request immediately.
    const result =
      checkThreat(agent);

    const event =
      await buildSecurityEvent({
        id: Date.now(),

        agent,
        action,
        result,

        uniqueFiles:
          req.body.uniqueFiles ?? 1,

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

    console.log(
      `Event stored: ${event.agent} | ` +
        `Request ${event.requestCount} | ` +
        `Risk ${event.risk}`
    );

    return res.json({
      status:
        event.risk,

      combinedRiskScore:
        event.combinedRiskScore,

      requests:
        event.requestCount,

      threshold:
        event.threshold,

      baselineExceeded:
        event.baselineExceeded,

      entityType:
        event.entityType,

      mlAvailable:
        event.mlAvailable,

      mlPrediction:
        event.mlPrediction,

      mlIsAnomaly:
        event.mlIsAnomaly,

      mlAnomalyScore:
        event.mlAnomalyScore,

      mlError:
        event.mlError,

      riskBreakdown:
        event.riskBreakdown,

      features:
        event.features,

      tokenRevoked:
        isTokenRevoked(),
    });
  } catch (error) {
    console.error(
      "Failed to process security event:",
      error.message
    );

    return res.status(500).json({
      error:
        "Failed to process security event",
    });
  }
});

/**
 * Built-in attack simulation.
 */
app.post(
  "/simulate-attack",
  async (req, res) => {
    try {
      const generatedEvents = [];

      const agent =
        "GitHub AI Agent";

      // Send 10 events so the threshold of 8 can be exceeded.
      for (let i = 1; i <= 10; i++) {
        const result =
          checkThreat(agent);

        const event =
          await buildSecurityEvent({
            id:
              Date.now() + i,

            agent,

            action:
              `Rapid repository read ${i}`,

            result,

            uniqueFiles:
              Math.min(12, i + 3),

            failedRequests:
              i >= 3
                ? Math.min(5, i - 1)
                : 1,

            sensitiveFileAccesses:
              i >= 2
                ? Math.min(4, i - 1)
                : 1,
          });

        if (
          event.risk === "HIGH" &&
          !isTokenRevoked()
        ) {
          revokeToken();
        }

        events.push(event);
        generatedEvents.push(event);

        console.log(
          `Simulation event ${i}: ` +
            `${event.risk}, ` +
            `requests=${event.requestCount}`
        );
      }

      return res.json({
        message:
          "Hybrid attack simulation completed",

        tokenRevoked:
          isTokenRevoked(),

        generatedEvents,
      });
    } catch (error) {
      console.error(
        "Attack simulation failed:",
        error.message
      );

      return res.status(500).json({
        error:
          "Attack simulation failed",
      });
    }
  }
);

/**
 * Return all dashboard events.
 */
app.get("/events", (req, res) => {
  // Prevent browser or deployment cache.
  res.set({
    "Cache-Control":
      "no-store, no-cache, must-revalidate, proxy-revalidate",

    Pragma:
      "no-cache",

    Expires:
      "0",

    "Surrogate-Control":
      "no-store",
  });

  return res.json(events);
});

/**
 * Return current system status.
 */
app.get("/status", (req, res) => {
  const latestEvent =
    events.length > 0
      ? events[events.length - 1]
      : null;

  return res.json({
    backendOnline:
      true,

    mlEnabled:
      USE_ML,

    tokenRevoked:
      isTokenRevoked(),

    threatLevel:
      latestEvent?.risk || "LOW",

    combinedRiskScore:
      latestEvent?.combinedRiskScore || 0,

    mlPrediction:
      latestEvent?.mlPrediction ||
      "NO DATA",

    mlAnomalyScore:
      latestEvent?.mlAnomalyScore || 0,

    totalEvents:
      events.length,

    latestEvent,
  });
});

/**
 * Reset the entire demo.
 */
app.post("/reset", (req, res) => {
  events = [];

  resetThreatDetector();

  if (
    typeof resetToken === "function"
  ) {
    resetToken();
  }

  return res.json({
    message:
      "ShadowGuard AI demo reset successfully",

    tokenRevoked:
      isTokenRevoked(),

    events: [],
  });
});

/**
 * Handle unknown routes.
 */
app.use((req, res) => {
  return res.status(404).json({
    error:
      "Route not found",
  });
});

/**
 * Start the server.
 */
app.listen(PORT, () => {
  console.log(
    `🚀 Server running on http://localhost:${PORT}`
  );

  console.log(
    `🧠 ML integration: ${
      USE_ML
        ? "enabled"
        : "disabled"
    }`
  );

  console.log(
    `🔗 ML service: ${ML_SERVICE_URL}`
  );

  console.log(
    `⏱️ ML timeout: ${ML_TIMEOUT_MS}ms`
  );
});