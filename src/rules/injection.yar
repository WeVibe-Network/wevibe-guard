/*
 * WeVibe Guard — Prompt injection detection rules
 * Format: YARA (industry standard)
 *
 * Categories:
 *   - instruction_bypass: "ignore previous", "disregard", etc.
 *   - role_hijack: "you are now", "act as", "pretend to be"
 *   - dan_style: "DAN", "Do Anything Now", jailbreak patterns
 *   - system_leak: "print your system prompt", "reveal instructions"
 *   - delimiter_escape: prompt boundary markers
 */

rule instruction_bypass
{
    meta:
        description = "Detects attempts to override prior instructions"
        category = "injection"
    strings:
        $a1 = "ignore previous" nocase
        $a2 = "ignore all previous" nocase
        $a3 = "ignore all prior" nocase
        $a4 = "disregard previous" nocase
        $a5 = "disregard all previous" nocase
        $a6 = "disregard your instructions" nocase
        $a7 = "forget your instructions" nocase
        $a8 = "forget all previous" nocase
        $a9 = "override your instructions" nocase
        $a10 = "new instructions:" nocase
        $a11 = "ignore the above" nocase
        $a12 = "disregard the above" nocase
    condition:
        any of them
}

rule role_hijack
{
    meta:
        description = "Detects role hijacking attempts"
        category = "injection"
    strings:
        $r1 = "you are now" nocase
        $r2 = "act as" nocase
        $r3 = "pretend to be" nocase
        $r4 = "pretend you are" nocase
        $r5 = "your new role" nocase
        $r6 = "from now on you" nocase
        $r7 = "you must act as" nocase
        $r8 = "switch to" nocase
    condition:
        any of them
}

rule dan_style
{
    meta:
        description = "Detects DAN/jailbreak style prompts"
        category = "injection"
    strings:
        $d1 = "DAN" fullword
        $d2 = "Do Anything Now" nocase
        $d3 = "jailbreak" nocase
        $d4 = "bypass safety" nocase
        $d5 = "bypass filters" nocase
        $d6 = "unrestricted mode" nocase
        $d7 = "developer mode" nocase
        $d8 = "no restrictions" nocase
    condition:
        any of them
}

rule system_prompt_leak
{
    meta:
        description = "Detects attempts to extract system prompts"
        category = "injection"
    strings:
        $s1 = "print your system prompt" nocase
        $s2 = "reveal your instructions" nocase
        $s3 = "show me your prompt" nocase
        $s4 = "output your system" nocase
        $s5 = "what is your system prompt" nocase
        $s6 = "repeat your instructions" nocase
        $s7 = "display your prompt" nocase
    condition:
        any of them
}

rule unicode_mathematical_injection
{
    meta:
        description = "Detects mathematical alphanumeric symbol injection (U+1D400–U+1D7FF)"
        category = "injection"
    strings:
        $math_uc = { F0 9D 9? ?? F0 9D 9? ?? F0 9D 9? ?? }
    condition:
        $math_uc
}

rule delimiter_escape
{
    meta:
        description = "Detects prompt delimiter escape attempts"
        category = "injection"
    strings:
        $de1 = "```system" nocase
        $de2 = "###SYSTEM" nocase
        $de3 = "---BEGIN SYSTEM---" nocase
        $de4 = "<|system|>" nocase
        $de5 = "[SYSTEM]" nocase
        $de6 = "<<SYS>>" nocase
        $de7 = "[/INST]" nocase
        $de8 = "</s>" nocase
    condition:
        any of them
}
