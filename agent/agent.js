require("dotenv").config();
const axios = require("axios");

const OWNER = "ritikavrmaa";
const REPO = "shadowguard-demo";
const BACKEND_URL = "https://shadowguard-backend.onrender.com";

async function readReadme() {
  try {
    if (!process.env.GITHUB_TOKEN) {
      throw new Error("GITHUB_TOKEN is missing from the .env file");
    }

    console.log("Starting GitHub AI Agent...");

    await axios.get(
      `https://api.github.com/repos/${OWNER}/${REPO}/contents/README.md`,
      {
        headers: {
          Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28"
        },
        timeout: 30000
      }
    );

    console.log("README Read Successfully");
    console.log("Sending activity to ShadowGuard backend...");

    const response = await axios.post(
      `${BACKEND_URL}/log`,
      {
        agent: "GitHub AI Agent",
        action: "Read README.md",
        repository: REPO,
        identityType: "AI_AGENT",
        file: "README.md",
        status: "SUCCESS"
      },
      {
        headers: {
          "Content-Type": "application/json"
        },
        timeout: 60000
      }
    );

    console.log("Activity logged successfully");
    console.log(response.data);
  } catch (error) {
    console.error("Agent failed");

    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Response:", error.response.data);
    } else {
      console.error("Error:", error.message);
    }
  }
}

readReadme();
