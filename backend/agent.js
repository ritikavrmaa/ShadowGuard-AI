const axios = require("axios");

async function sendActivity() {
  try {
    const response = await axios.post(
      "http://127.0.0.1:5000/log",
      {
        agent: "GitHub AI Agent",
        action: "Read README.md",
      },
      {
        timeout: 5000,
      }
    );

    console.log("Activity logged successfully:");
    console.log(response.data);
  } catch (error) {
    console.error("Request failed");

    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Response:", error.response.data);
    } else if (error.request) {
      console.error("No response received from backend.");
      console.error("Check whether server.js is running on port 5000.");
    } else {
      console.error("Error:", error.message);
    }
  }
}

sendActivity();