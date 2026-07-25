const axios = require("axios");

const API_URL =
  "https://shadowguard-backend.onrender.com/log";

const wait = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function simulateCompromisedRahul() {
  try {
    for (let i = 1; i <= 10; i++) {
      const response = await axios.post(
        API_URL,
        {
          agent: "Developer Rahul",
          action: `Suspicious repository access ${i}`,

          // Abnormal human activity features
          uniqueFiles: Math.min(12, i + 4),
          failedRequests: Math.min(
            5,
            Math.floor(i / 2)
          ),
          sensitiveFileAccesses: Math.min(
            4,
            Math.floor(i / 3) + 1
          ),
        },
        {
          timeout: 30000,
        }
      );

      console.log(`Event ${i}:`, response.data);

      // Prevent ML service rate-limit errors.
      if (i < 10) {
        console.log("Waiting before next event...");
        await wait(2000);
      }
    }

    console.log(
      "Compromised Rahul simulation completed successfully."
    );
  } catch (error) {
    console.error(
      "Compromised Rahul simulation failed:",
      error.response?.data || error.message
    );
  }
}

simulateCompromisedRahul();