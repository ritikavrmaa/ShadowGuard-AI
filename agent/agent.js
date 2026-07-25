const axios = require("axios");
require("dotenv").config();

const USERNAME = "ritikavrmaa";
const REPO = "shadowguard-demo";

async function readReadme() {

    try {

        const response = await axios.get(
            `https://api.github.com/repos/${USERNAME}/${REPO}/contents/README.md`,
            {
                headers: {
                    Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
                    Accept: "application/vnd.github+json"
                }
            }
        );

        console.log("✅ README Read Successfully");

        await axios.post("http://localhost:5000/log", {

            agent: "GitHub AI Agent",

            action: "Read README.md",

            repository: REPO,

            status: "SUCCESS"

        });

    } catch (error) {

        console.log(error.response?.data || error.message);

    }

}

readReadme();