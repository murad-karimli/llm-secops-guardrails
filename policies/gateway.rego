package secops.gateway

import future.keywords.if
import future.keywords.in

default allow := false
default risk_score := 0

# Calculate cumulative risk score based on adversarial patterns and restricted targets
risk_score := score if {
    lower_prompt := lower(input.prompt)
    
    # +40 points for each adversarial override keyword detected
    override_hits := [kw | kw := data.high_risk_keywords[_]; contains(lower_prompt, kw)]
    
    # +35 points for each restricted data target requested
    target_hits := [tg | tg := data.restricted_targets[_]; contains(lower_prompt, tg)]
    
    score := (count(override_hits) * 40) + (count(target_hits) * 35)
}

# Allow request if calculated risk score is within enterprise threshold
allow if {
    risk_score <= data.max_allowed_risk_score
}

# Provide deterministic block reasons for SOC telemetry
block_reasons[reason] if {
    lower_prompt := lower(input.prompt)
    kw := data.high_risk_keywords[_]
    contains(lower_prompt, kw)
    reason := sprintf("Adversarial framing signature detected: '%s'", [kw])
}

block_reasons[reason] if {
    lower_prompt := lower(input.prompt)
    tg := data.restricted_targets[_]
    contains(lower_prompt, tg)
    reason := sprintf("Unauthorized access attempt to restricted attribute: '%s'", [tg])
}