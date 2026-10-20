import type { AiRiskAdjustment, RiskContribution, ScanVerdict, XaiExplanation } from "./types";

export type { AiRiskAdjustment, RiskContribution, XaiExplanation } from "./types";

export function verdictForScore(score: number): ScanVerdict {
  if (score >= 70) return "MALICIOUS";
  if (score >= 45) return "SUSPICIOUS";
  if (score >= 20) return "LOW_RISK";
  return "SAFE";
}

export function createXaiExplanation(
  ruleScore: number,
  finalScore: number,
  verdict: ScanVerdict,
  contributions: RiskContribution[],
  aiAdjustment: AiRiskAdjustment | null = null,
): XaiExplanation {
  const contributionTotal = contributions.reduce((total, item) => total + item.points, 0);
  if (contributionTotal !== ruleScore) {
    throw new Error("Explanation contributions do not match the rule-based score.");
  }
  if (verdictForScore(finalScore) !== verdict) {
    throw new Error("Explanation score does not match the final verdict.");
  }
  if (
    aiAdjustment &&
    (aiAdjustment.from !== Math.min(100, ruleScore) ||
      aiAdjustment.to !== Math.max(aiAdjustment.from, 75) ||
      aiAdjustment.confidence <= 80 ||
      aiAdjustment.tacticsCount < 2)
  ) {
    throw new Error("Explanation AI adjustment does not match the escalation policy.");
  }
  if (finalScore !== Math.min(100, Math.max(ruleScore, aiAdjustment?.to ?? ruleScore))) {
    throw new Error("Explanation final score does not match the scoring rules.");
  }

  const verdictBasis =
    verdict === "MALICIOUS"
      ? "Final score is 70 or higher."
      : verdict === "SUSPICIOUS"
        ? "Final score is 45–69."
        : verdict === "LOW_RISK"
          ? "Final score is 20–44."
          : "Final score is below 20.";

  return {
    method: "Weighted URL rules",
    ruleScore,
    scoreCap: 100,
    finalScore,
    verdictBasis,
    contributions: [...contributions],
    aiAdjustment,
  };
}
