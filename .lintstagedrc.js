const { ESLint } = require("eslint");

const eslint = new ESLint();

const asyncFilter = async (arr, predicate) => {
  const results = await Promise.all(arr.map(predicate));
  return arr.filter((_v, index) => results[index]);
};
// Awaits and negates a promised result.
const negate = async (prom) => !(await prom);

module.exports = {
  "*.{json,md,html,js,jsx,ts,tsx,css,scss,yml}": ["prettier --write"],
  "*.{js,ts,tsx,jsx}": async (files) => {
    // Only lint files that are not ignored by ESLint.
    const lintedFiles = await asyncFilter(files, (f) =>
      negate(eslint.isPathIgnored(f))
    );
    return [`eslint --fix --max-warnings=0 ${lintedFiles.join(" ")}`];
  },
};
