const axios = require("axios");
require("dotenv").config();

const GITHUB_USERNAME = "ritikavrmaa";
const REPO_NAME = "shadowguard-demo";

async function getRepositoryFiles() {
    try {
        const response = await axios.get(
            `https://api.github.com/repos/${GITHUB_USERNAME}/${REPO_NAME}/contents`,
            {
                headers: {
                    Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
                    Accept: "application/vnd.github+json"
                }
            }
        );

        return response.data;

    } catch (error) {
        console.error("GitHub Error:", error.response?.data || error.message);
    }
}

module.exports = { getRepositoryFiles };