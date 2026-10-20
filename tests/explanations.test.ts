import assert from "node:assert/strict";
import test from "node:test";
import { createXaiExplanation, verdictForScore, type RiskContribution } from "../src/explanations";

test("explanation sums exact rule contributions and reports capped scores", () => {
  const contributions: RiskContribution[] = [
    { feature: "Lookalike characters", points: 50, evidence: "Detected in hostname." },
    { feature: "Suspicious keywords", points: 25, evidence: "Two keywords found." },
    { feature: "Unencrypted HTTP", points: 15, evidence: "HTTP used." },
    { feature: "DNS failure", points: 30, evidence: "Hostname did not resolve." },
  ];

  const explanation = createXaiExplanation(120, 100, "MALICIOUS", contributions);

  assert.equal(explanation.ruleScore, 120);
  assert.equal(explanation.finalScore, 100);
  assert.equal(explanation.contributions.reduce((sum, item) => sum + item.points, 0), 120);
  assert.equal(explanation.aiAdjustment, null);
});

test("explanation distinguishes Gemini escalation from URL rule contributions", () => {
  const contributions: RiskContribution[] = [
    { feature: "Unencrypted HTTP", points: 15, evidence: "HTTP used." },
  ];

  const explanation = createXaiExplanation(15, 75, "MALICIOUS", contributions, {
    from: 15,
    to: 75,
    confidence: 91,
    tacticsCount: 2,
  });

  assert.equal(explanation.finalScore, 75);
  assert.deepEqual(explanation.aiAdjustment, { from: 15, to: 75, confidence: 91, tacticsCount: 2 });
  assert.equal(verdictForScore(explanation.finalScore), "MALICIOUS");
});

test("safe classifications clearly allow an empty list of positive risk contributions", () => {
  const explanation = createXaiExplanation(0, 0, "SAFE", []);

  assert.equal(explanation.verdictBasis, "Final score is below 20.");
  assert.deepEqual(explanation.contributions, []);
});

test("explanation rejects score or verdict disagreement", () => {
  assert.throws(
    () => createXaiExplanation(20, 20, "SAFE", [{ feature: "Rule", points: 20, evidence: "Matched." }]),
    /does not match the final verdict/,
  );
  assert.throws(
    () => createXaiExplanation(21, 20, "LOW_RISK", [{ feature: "Rule", points: 20, evidence: "Matched." }]),
    /do not match the rule-based score/,
  );
  assert.throws(
    () => createXaiExplanation(15, 75, "MALICIOUS", [{ feature: "Rule", points: 15, evidence: "Matched." }], {
      from: 15,
      to: 75,
      confidence: 80,
      tacticsCount: 2,
    }),
    /does not match the escalation policy/,
  );
});

test("verdict thresholds match scanner classification boundaries", () => {
  assert.deepEqual(
    [0, 19, 20, 44, 45, 69, 70].map(verdictForScore),
    ["SAFE", "SAFE", "LOW_RISK", "LOW_RISK", "SUSPICIOUS", "SUSPICIOUS", "MALICIOUS"],
  );
});
