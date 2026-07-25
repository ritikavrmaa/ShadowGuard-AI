// detector.js
const { getBaseline } = require("./baselines");

const WINDOW_MS = 10000;
const DEFAULT_THRESHOLD = 5;

const activity = {};

function checkThreat(entityId) {
  const now = Date.now();

  if (!activity[entityId]) {
    activity[entityId] = [];
  }

  activity[entityId].push(now);

  // Sliding window: only keep requests from
  // the previous 10 seconds.
  activity[entityId] =
    activity[entityId].filter(
      (time) => now - time <= WINDOW_MS
    );

  const requestCount =
    activity[entityId].length;

  const baseline = getBaseline(entityId);

  const threshold =
    baseline?.normalActionLimit ||
    DEFAULT_THRESHOLD;

  const suspicious =
    requestCount > threshold;

  return {
    suspicious,
    count: requestCount,
    threshold,
    baseline,
    windowMs: WINDOW_MS,
  };
}

function resetThreatDetector() {
  for (const entityId of Object.keys(activity)) {
    delete activity[entityId];
  }
}

module.exports = {
  checkThreat,
  resetThreatDetector,
};
