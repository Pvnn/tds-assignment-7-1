// Simple smoke test: starts the app in-process, fires a few payloads at it,
// and fails the workflow (non-zero exit code) if anything looks wrong.
const { app, evaluate } = require("../server");

const safePayload = {
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/feature-x",
  workflow: {
    trigger: "pull_request",
    permissions: { contents: "read", packages: "write", "id-token": "none" },
    testsPassed: true,
    matrixComplete: true,
    failFast: false,
    actions: [
      { owner: "actions", name: "checkout", ref: "v4" },
      { owner: "docker", name: "build-push-action", ref: "a".repeat(40) },
    ],
  },
  image: {
    multiStage: true,
    runsAsRoot: false,
    secretMode: "buildkit",
    criticalVulnerabilities: 0,
    digestPinned: true,
  },
};

const unsafePayload = {
  target: "production",
  event: "pull_request",
  ref: "refs/heads/feature-x",
  workflow: {
    trigger: "pull_request_target",
    permissions: { contents: "read", packages: "write", "id-token": "write" },
    testsPassed: false,
    matrixComplete: false,
    failFast: true,
    actions: [{ owner: "docker", name: "build-push-action", ref: "not-a-sha" }],
  },
  image: {
    multiStage: false,
    runsAsRoot: true,
    secretMode: "arg",
    criticalVulnerabilities: 3,
    digestPinned: false,
  },
};

let failures = 0;

function check(name, condition) {
  if (!condition) {
    failures++;
    console.error(`FAIL: ${name}`);
  } else {
    console.log(`PASS: ${name}`);
  }
}

const safeResult = evaluate(safePayload);
check("safe payload promotes", safeResult.decision === "promote");
check("safe payload has no violations", safeResult.violations.length === 0);

const unsafeResult = evaluate(unsafePayload);
check("unsafe payload blocks", unsafeResult.decision === "block");
check(
  "unsafe payload catches EXCESS_PERMISSION",
  unsafeResult.violations.includes("EXCESS_PERMISSION")
);
check(
  "unsafe payload catches UNSAFE_PR_TRIGGER",
  unsafeResult.violations.includes("UNSAFE_PR_TRIGGER")
);
check(
  "unsafe payload catches TESTS_INCOMPLETE",
  unsafeResult.violations.includes("TESTS_INCOMPLETE")
);
check(
  "unsafe payload catches MUTABLE_ACTION",
  unsafeResult.violations.includes("MUTABLE_ACTION")
);
check(
  "unsafe payload catches SINGLE_STAGE_IMAGE",
  unsafeResult.violations.includes("SINGLE_STAGE_IMAGE")
);
check("unsafe payload catches ROOT_RUNTIME", unsafeResult.violations.includes("ROOT_RUNTIME"));
check(
  "unsafe payload catches SECRET_IN_LAYER",
  unsafeResult.violations.includes("SECRET_IN_LAYER")
);
check("unsafe payload catches CRITICAL_CVE", unsafeResult.violations.includes("CRITICAL_CVE"));
check(
  "unsafe payload catches UNPINNED_IMAGE",
  unsafeResult.violations.includes("UNPINNED_IMAGE")
);
check(
  "unsafe payload catches INVALID_PRODUCTION_REF",
  unsafeResult.violations.includes("INVALID_PRODUCTION_REF")
);
check(
  "unsafe payload catches APPROVAL_REQUIRED",
  unsafeResult.violations.includes("APPROVAL_REQUIRED")
);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
} else {
  console.log("\nAll checks passed.");
  process.exit(0);
}
