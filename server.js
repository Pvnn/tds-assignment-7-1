const express = require("express");
const app = express();
app.use(express.json());

const SHA_RE = /^[0-9a-f]{40}$/; // full 40-char lowercase hex commit SHA

function evaluate(body) {
  const violations = [];

  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const wf = body.workflow || {};
  const img = body.image || {};
  const perms = wf.permissions || {};
  const actions = wf.actions || [];

  // 1. Permissions must be EXACTLY these three, nothing more, nothing less.
  const required = { contents: "read", packages: "write", "id-token": "none" };
  const requiredKeys = Object.keys(required);
  const actualKeys = Object.keys(perms);
  const permsExact =
    actualKeys.length === requiredKeys.length &&
    requiredKeys.every((k) => perms[k] === required[k]);
  if (!permsExact) violations.push("EXCESS_PERMISSION");

  // 2. pull_request_target is never allowed as the trigger.
  if (wf.trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // 3. Tests must fully pass: whole matrix done, no fail-fast, tests green.
  if (wf.testsPassed !== true || wf.matrixComplete !== true || wf.failFast === true) {
    violations.push("TESTS_INCOMPLETE");
  }

  // 4. Action pinning: "actions"-owned may use a tag, everyone else needs a full SHA.
  const hasMutableAction = actions.some((a) => {
    if (a.owner === "actions") return false; // tag allowed
    return !SHA_RE.test(String(a.ref || ""));
  });
  if (hasMutableAction) violations.push("MUTABLE_ACTION");

  // 5. Image hardening checks.
  if (img.multiStage !== true) violations.push("SINGLE_STAGE_IMAGE");
  if (img.runsAsRoot !== false) violations.push("ROOT_RUNTIME");
  if (!["none", "buildkit"].includes(img.secretMode)) violations.push("SECRET_IN_LAYER");
  if (!(Number(img.criticalVulnerabilities) === 0)) violations.push("CRITICAL_CVE");
  if (img.digestPinned !== true) violations.push("UNPINNED_IMAGE");

  // 6. Production has two EXTRA requirements on top of everything above.
  if (target === "production") {
    if (!(event === "push" && ref === "refs/heads/main")) {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (wf.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

app.post("/release-gate", (req, res) => {
  try {
    res.json(evaluate(req.body));
  } catch (err) {
    res.status(400).json({ decision: "block", violations: ["MALFORMED_REQUEST"] });
  }
});

// Health check so Render (and you) can confirm it's alive.
app.get("/", (_req, res) => res.send("release-gate is up"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`release-gate listening on ${PORT}`));

module.exports = { evaluate, app };
