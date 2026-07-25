const axios = require("axios");

const API_URL = "http://127.0.0.1:5000";

async function runSensitiveAttack() {
  try {
    for (let i = 1; i <= 6; i++) {
      const response = await axios.post(`${API_URL}/log`, {
        agent: "Developer Rahul",
        action: `Sensitive file access ${i}`,
        uniqueFiles: 10,
        failedRequests: 4,
        sensitiveFileAccesses: 3,
      });

      console.log(`Event ${i}:`, response.data);
    }
  } catch (error) {
    console.error(
      "Sensitive attack failed:",
      error.response?.data || error.message
    );
  }
}

runSensitiveAttack();