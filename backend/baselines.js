// baselines.js

const baselines = {
  "Developer Rahul": {
    entityType: "HUMAN",
    normalActionLimit: 8,
    description: "Developer with regular access to project files",
  },

  "GitHub AI Agent": {
    entityType: "MACHINE",
    normalActionLimit: 3,
    description: "Autonomous agent with limited repository access",
  },
};

function getBaseline(entityName) {
  return baselines[entityName] || null;
}

module.exports = {
  baselines,
  getBaseline,
};