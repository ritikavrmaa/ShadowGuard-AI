const axios = require("axios");

async function simulateNormalUser() {
  try {
    const response = await axios.post(
      "http://127.0.0.1:5000/log",
      {
        agent: "Developer Rahul",
        action: "Read project files",
      },
      {
        timeout: 5000,
      }
    );

    console.log("Normal user activity logged:");
    console.log(response.data);
  } catch (error) {
    console.error("Request failed");

    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Response:", error.response.data);
    } else {
      console.error("Error:", error.message);
    }
  }
}

simulateNormalUser();