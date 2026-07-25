const axios = require("axios");

const API_URL = "http://127.0.0.1:5000";

async function simulateCompromisedRahul() {
  try {
    for (let i = 1; i <= 10; i++) {
      const response = await axios.post(`${API_URL}/log`, {
        agent: "Developer Rahul",
        action: `Suspicious repository access ${i}`,

        // Abnormal human activity features
        uniqueFiles: Math.min(12, i + 4),
        failedRequests: Math.min(5, Math.floor(i / 2)),
        sensitiveFileAccesses: Math.min(4, Math.floor(i / 3) + 1),
      });

      console.log(`Event ${i}:`, response.data);
    }
  } catch (error) {
    console.error(
      "Compromised Rahul simulation failed:",
      error.response?.data || error.message
    );
  }
}

simulateCompromisedRahul();