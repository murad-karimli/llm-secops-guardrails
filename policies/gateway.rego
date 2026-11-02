package secops.gateway

import future.keywords.if
import future.keywords.in

default allow := false
default risk_score := 0

# Calculate cumulative risk score based on adversarial patterns, evasion techniques, and restricted targets
risk_score := score if {
    lower_prompt := lower(input.prompt)
    
    # +40 points for each adversarial override keyword
    override_hits := [kw | kw := data.high_risk_keywords[_]; contains(lower_prompt, kw)]
    
    # +45 points for filter evasion / encoding / obfuscation attempts (M3.2.1 & M5.3.1)
    evasion_hits := [ev | ev := data.evasion_indicators[_]; contains(lower_prompt, ev)]
    
    # +35 points for each restricted data target requested
    target_hits := [tg | tg := data.restricted_targets[_]; contains(lower_prompt, tg)]
    
    score := (count(override_hits) * 40) + (count(evasion_hits) * 45) + (count(target_hits) * 35)
}

allow if {
    risk_score <= data.max_allowed_risk_score
}

block_reasons[reason] if {
    lower_prompt := lower(input.prompt)
    kw := data.high_risk_keywords[_]
    contains(lower_prompt, kw)
    reason := sprintf("Adversarial framing signature: '%s' [MITRE: AML.T0051.000]", [kw])
}

block_reasons[reason] if {
    lower_prompt := lower(input.prompt)
    ev := data.evasion_indicators[_]
    contains(lower_prompt, ev)
    reason := sprintf("Guardrail evasion/encoding technique: '%s' [MITRE: AML.T0043]", [ev])
}

block_reasons[reason] if {
    lower_prompt := lower(input.prompt)
    tg := data.restricted_targets[_]
    contains(lower_prompt, tg)
    reason := sprintf("Restricted asset probe: '%s' [MITRE: AML.T0024]", [tg])
}