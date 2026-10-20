# Scan explanations

The URL scanner uses a weighted set of deterministic URL and DNS rules rather than a trained classification model, so SHAP is not applicable. Each rule that adds risk points is recorded with its exact point value and a short description of the observed signal. The explanation's rule score is the sum of those contributions; the displayed score is capped at 100. Passing checks do not subtract points.

The score maps to the verdict at these boundaries: below 20 is `SAFE`, 20–44 is `LOW_RISK`, 45–69 is `SUSPICIOUS`, and 70 or more is `MALICIOUS`. When Gemini is enabled, the existing escalation policy can raise a local score below 70 to 75 if confidence exceeds 80 and at least two social-engineering tactics are returned. That adjustment is disclosed separately and is not represented as a URL-feature contribution. If the explanation cannot be reconciled with the score and verdict, scan processing returns an error rather than a misleading explanation.
