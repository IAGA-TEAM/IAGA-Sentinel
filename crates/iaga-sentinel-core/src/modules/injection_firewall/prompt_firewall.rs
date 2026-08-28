//! LAYER 7, Prompt Injection Firewall
//!
//! 3-stage pipeline:
//!   Stage 1: Signature scan (<1ms), 25+ known injection patterns
//!   Stage 2: Structural analysis (<5ms), entropy, role confusion, encoding tricks
//!   Stage 3: Semantic heuristics (<200ms)

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

// ── Types ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallResult {
    pub blocked: bool,
    pub risk_score: u32,
    pub stages_run: u32,
    pub stage_results: Vec<StageResult>,
    pub summary: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageResult {
    pub stage: u32,
    pub name: String,
    pub triggered: bool,
    pub score: u32,
    pub matches: Vec<PatternMatch>,
    pub duration_us: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternMatch {
    pub pattern_name: String,
    pub severity: String,
    pub matched_text: String,
    pub category: String,
}

// ── Stats ──

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallStats {
    pub total_scanned: u64,
    pub total_blocked: u64,
    pub stage1_catches: u64,
    pub stage2_catches: u64,
    pub stage3_catches: u64,
    pub false_positives_reported: u64,
}

static STATS: Lazy<Mutex<FirewallStats>> = Lazy::new(|| Mutex::new(FirewallStats::default()));

pub fn get_firewall_stats() -> FirewallStats {
    STATS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn report_false_positive() {
    STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .false_positives_reported += 1;
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Truncate `s` to at most `max_bytes`, snapping the end down to a UTF-8 char
/// boundary so the slice can never split a multi-byte codepoint.
///
/// SND-FIREWALL-PANIC: the firewall is the first gate on every `/v1/inspect`
/// over a fully attacker-controlled payload. The previous `&text[start..start+N]`
/// truncation panicked ("byte index is not a char boundary") when a match longer
/// than the cap had a multi-byte char straddling byte `start+N`, turning a crafted
/// payload into a per-request DoS before any verdict was produced. This helper is
/// allocation-free and boundary-safe; the result is diagnostic text only and never
/// feeds scoring or the signed receipt.
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Normalize the compatibility characters attackers use most often without a
/// Unicode-normalization dependency. Full-width ASCII is losslessly mapped;
/// mixed Latin/Cyrillic tokens are handled separately below.
fn normalize_compat_ascii(text: &str) -> Cow<'_, str> {
    if !text
        .chars()
        .any(|c| matches!(c, '\u{3000}' | '\u{FF01}'..='\u{FF5E}'))
    {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| match c {
                '\u{3000}' => ' ',
                '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
                _ => c,
            })
            .collect(),
    )
}

fn is_cyrillic_confusable(c: char) -> bool {
    matches!(
        c,
        'а' | 'е'
            | 'і'
            | 'о'
            | 'р'
            | 'с'
            | 'у'
            | 'х'
            | 'А'
            | 'В'
            | 'Е'
            | 'І'
            | 'К'
            | 'М'
            | 'Н'
            | 'О'
            | 'Р'
            | 'С'
            | 'Т'
            | 'Х'
    )
}

fn contains_mixed_script_token(text: &str) -> bool {
    let (mut latin, mut cyrillic) = (false, false);
    for c in text.chars() {
        if c.is_alphanumeric() || c == '_' {
            latin |= c.is_ascii_alphabetic();
            cyrillic |= is_cyrillic_confusable(c);
            if latin && cyrillic {
                return true;
            }
        } else {
            latin = false;
            cyrillic = false;
        }
    }
    false
}

// ── Stage 1: Signature Scan ──

struct InjectionSignature {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    score: u32,
    category: &'static str,
}

struct CompiledSignature {
    name: &'static str,
    regex: Regex,
    severity: &'static str,
    score: u32,
    category: &'static str,
}

static COMPILED_SIGNATURES: Lazy<Vec<CompiledSignature>> = Lazy::new(|| {
    signatures()
        .into_iter()
        .filter_map(|sig| {
            Regex::new(sig.pattern).ok().map(|re| CompiledSignature {
                name: sig.name,
                regex: re,
                severity: sig.severity,
                score: sig.score,
                category: sig.category,
            })
        })
        .collect()
});

fn signatures() -> Vec<InjectionSignature> {
    vec![
        // Direct instruction override
        InjectionSignature {
            name: "ignore_previous",
            pattern: r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|directives)",
            severity: "critical",
            score: 95,
            category: "instruction_override",
        },
        InjectionSignature {
            name: "disregard_instructions",
            pattern: r"(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|programming)",
            severity: "critical",
            score: 95,
            category: "instruction_override",
        },
        InjectionSignature {
            name: "new_instructions",
            pattern: r"(?i)(new|updated|revised)\s+instructions?\s*:",
            severity: "high",
            score: 75,
            category: "instruction_override",
        },
        InjectionSignature {
            name: "forget_everything",
            pattern: r"(?i)forget\s+(everything|all)\s+(you|that)",
            severity: "critical",
            score: 90,
            category: "instruction_override",
        },
        InjectionSignature {
            name: "override_system",
            pattern: r"(?i)(override|bypass|skip)\s+(system|safety|security)\s+(prompt|rules|filters|checks)",
            severity: "critical",
            score: 95,
            category: "instruction_override",
        },
        // Role manipulation
        InjectionSignature {
            name: "act_as",
            pattern: r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you're)|roleplay\s+as)\s+",
            severity: "high",
            score: 80,
            category: "role_manipulation",
        },
        InjectionSignature {
            name: "system_prompt_leak",
            pattern: r"(?i)(show|reveal|display|print|output)\s+(your|the)\s+(system\s+prompt|instructions|rules|directives)",
            severity: "critical",
            score: 90,
            category: "role_manipulation",
        },
        InjectionSignature {
            name: "jailbreak_dan",
            pattern: r"(?i)(\bDAN\b|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b|\bgod\s+mode\b|\bsudo\s+mode\b)",
            severity: "critical",
            score: 95,
            category: "role_manipulation",
        },
        InjectionSignature {
            name: "hypothetical_framing",
            pattern: r"(?i)(hypothetically|in\s+theory|just\s+for\s+fun|as\s+a\s+thought\s+experiment)\s*.*(execute|run|delete|hack|bypass)",
            severity: "high",
            score: 70,
            category: "role_manipulation",
        },
        // Data exfiltration
        InjectionSignature {
            name: "exfil_curl",
            pattern: r"(?is)(curl|wget)\s+.*\|\s*(sh|bash)\b",
            severity: "critical",
            score: 95,
            category: "exfiltration",
        },
        InjectionSignature {
            name: "exfil_webhook",
            pattern: r"(?i)(webhook\.site|requestbin|pipedream|ngrok|burp)",
            severity: "high",
            score: 85,
            category: "exfiltration",
        },
        InjectionSignature {
            name: "exfil_base64",
            pattern: r"(?i)(base64|btoa|atob)\s*(encode|decode)?\s*.*\s*(send|post|curl|fetch|http)",
            severity: "high",
            score: 80,
            category: "exfiltration",
        },
        InjectionSignature {
            name: "exfil_env_vars",
            pattern: r"(?i)(echo|print|cat|type)\s+.*(\$\{?\w*KEY\w*\}?|\$\{?\w*SECRET\w*\}?|\$\{?\w*TOKEN\w*\}?|\$\{?\w*PASS\w*\}?)",
            severity: "critical",
            score: 90,
            category: "exfiltration",
        },
        // Encoding/obfuscation
        InjectionSignature {
            name: "unicode_escape",
            pattern: r"\\u[0-9a-fA-F]{4}",
            severity: "medium",
            score: 40,
            category: "obfuscation",
        },
        InjectionSignature {
            name: "hex_escape",
            pattern: r"\\x[0-9a-fA-F]{2}",
            severity: "medium",
            score: 40,
            category: "obfuscation",
        },
        InjectionSignature {
            name: "zero_width_chars",
            pattern: r"[\u{200B}\u{200C}\u{200D}\u{FEFF}\u{2060}]",
            severity: "high",
            score: 80,
            category: "obfuscation",
        },
        // Indirect injection
        InjectionSignature {
            name: "markdown_injection",
            pattern: r"!\[.*\]\(https?://.*\)",
            severity: "medium",
            score: 50,
            category: "indirect_injection",
        },
        InjectionSignature {
            name: "html_injection",
            pattern: r"(?i)<\s*(script|iframe|object|embed)(?:\s|>)",
            severity: "high",
            score: 85,
            category: "indirect_injection",
        },
        InjectionSignature {
            name: "html_event_handler",
            pattern: r"(?is)<[^>]+\bon(?:error|load|click|focus|mouseover)\s*=",
            severity: "high",
            score: 85,
            category: "indirect_injection",
        },
        InjectionSignature {
            name: "html_script_url",
            pattern: r#"(?is)<[^>]+(?:href|src)\s*=\s*["']?\s*javascript:"#,
            severity: "critical",
            score: 90,
            category: "indirect_injection",
        },
        InjectionSignature {
            name: "data_uri",
            pattern: r"(?i)data:[a-z0-9.+-]+/[a-z0-9.+-]+;base64,",
            severity: "high",
            score: 75,
            category: "indirect_injection",
        },
        // Multi-turn manipulation
        InjectionSignature {
            name: "conversation_reset",
            pattern: r"(?i)(start\s+(a\s+)?new\s+conversation|clear\s+(the\s+)?context|reset\s+(the\s+)?session)",
            severity: "high",
            score: 70,
            category: "multi_turn",
        },
        InjectionSignature {
            name: "tool_abuse",
            pattern: r"(?i)(call|invoke|execute|run)\s+(the\s+)?(tool|function|api)\s+.*\s+(repeatedly|in\s+a\s+loop|continuously)",
            severity: "high",
            score: 80,
            category: "multi_turn",
        },
        // Privilege escalation
        InjectionSignature {
            name: "sudo_attempt",
            pattern: r"(?i)(sudo|su\s+-|runas|elevate|admin\s+mode)",
            severity: "high",
            score: 75,
            category: "privilege_escalation",
        },
        InjectionSignature {
            name: "capability_request",
            pattern: r"(?i)(grant|give|enable)\s+(me|yourself)\s+(access|permission|capability|privilege)",
            severity: "high",
            score: 70,
            category: "privilege_escalation",
        },
    ]
}

fn run_stage1(text: &str) -> StageResult {
    let start = now_us();
    let mut matches = Vec::new();
    let mut max_score: u32 = 0;

    for sig in COMPILED_SIGNATURES.iter() {
        if let Some(m) = sig.regex.find(text) {
            let matched = truncate_on_char_boundary(m.as_str(), 80);
            matches.push(PatternMatch {
                pattern_name: sig.name.to_string(),
                severity: sig.severity.to_string(),
                matched_text: matched.to_string(),
                category: sig.category.to_string(),
            });
            if sig.score > max_score {
                max_score = sig.score;
            }
        }
    }

    let triggered = !matches.is_empty();
    StageResult {
        stage: 1,
        name: "signature_scan".into(),
        triggered,
        score: max_score,
        matches,
        duration_us: now_us() - start,
    }
}

// ── Stage 2: Structural Analysis ──

fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = text.chars().count() as f64;
    for c in text.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn run_stage2(text: &str) -> StageResult {
    let start = now_us();
    let mut matches = Vec::new();
    let mut max_score: u32 = 0;
    let char_count = text.chars().count();

    // ponytail: this catches the practical mixed-script bypass without
    // pretending to implement the full Unicode confusables specification.
    // Replace with UTS #39 skeletons if non-Latin identifiers become normal
    // product input.
    if contains_mixed_script_token(text) {
        matches.push(PatternMatch {
            pattern_name: "homoglyph_attack".into(),
            severity: "high".into(),
            matched_text: "mixed Latin/Cyrillic token".into(),
            category: "obfuscation".into(),
        });
        max_score = 75;
    }

    // High entropy (potential obfuscation)
    let entropy = shannon_entropy(text);
    if entropy > 5.5 {
        let score = if entropy > 6.5 { 80 } else { 50 };
        matches.push(PatternMatch {
            pattern_name: "high_entropy".into(),
            severity: if entropy > 6.5 { "high" } else { "medium" }.into(),
            matched_text: format!("entropy={:.2}", entropy),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Language mixing (system/user role confusion)
    let role_markers = [
        "system:",
        "user:",
        "assistant:",
        "[INST]",
        "<<SYS>>",
        "</SYS>",
        "<|im_start|>",
        "<|im_end|>",
    ];
    let lower = text.to_lowercase();
    let role_count = role_markers
        .iter()
        .filter(|m| lower.contains(&m.to_lowercase()))
        .count();
    if role_count >= 2 {
        let score = 85;
        matches.push(PatternMatch {
            pattern_name: "role_boundary_confusion".into(),
            severity: "critical".into(),
            matched_text: format!("{} role markers found", role_count),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Delimiter injection
    let delimiters = ["```", "---", "===", "###", "***", "<<<", ">>>"];
    let delim_count = delimiters.iter().filter(|d| text.contains(**d)).count();
    if delim_count >= 3 {
        let score = 60;
        matches.push(PatternMatch {
            pattern_name: "delimiter_flooding".into(),
            severity: "medium".into(),
            matched_text: format!("{} delimiter types", delim_count),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Excessive special characters ratio
    let special_count = text
        .chars()
        .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
        .count();
    let total = char_count.max(1);
    let special_ratio = special_count as f64 / total as f64;
    if special_ratio > 0.4 && char_count > 50 {
        let score = 55;
        matches.push(PatternMatch {
            pattern_name: "special_char_heavy".into(),
            severity: "medium".into(),
            matched_text: format!("{:.0}% special chars", special_ratio * 100.0),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Repeated instruction patterns (hammering)
    let instruction_words = [
        "must",
        "always",
        "never",
        "important",
        "critical",
        "remember",
    ];
    let instruction_count: usize = instruction_words
        .iter()
        .map(|w| lower.matches(w).count())
        .sum();
    if instruction_count > 5 {
        let score = 65;
        matches.push(PatternMatch {
            pattern_name: "instruction_hammering".into(),
            severity: "high".into(),
            matched_text: format!("{} instruction keywords", instruction_count),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Length anomaly (very long payloads in tool calls are suspicious)
    if char_count > 5000 {
        let score = 35;
        matches.push(PatternMatch {
            pattern_name: "length_anomaly".into(),
            severity: "low".into(),
            matched_text: format!("{} chars", char_count),
            category: "structural".into(),
        });
        max_score = max_score.max(score);
    }

    // Nested encoding detection
    static RE_NESTED: Lazy<Option<Regex>> = Lazy::new(|| {
        Regex::new(r"(?i)(base64|atob|decode|unescape)\s*\(.*?(base64|atob|decode|unescape)").ok()
    });
    if let Some(ref re) = *RE_NESTED {
        if re.is_match(text) {
            let score = 85;
            matches.push(PatternMatch {
                pattern_name: "nested_encoding".into(),
                severity: "critical".into(),
                matched_text: "nested encoding/decoding detected".into(),
                category: "structural".into(),
            });
            max_score = max_score.max(score);
        }
    }

    let triggered = !matches.is_empty();
    StageResult {
        stage: 2,
        name: "structural_analysis".into(),
        triggered,
        score: max_score,
        matches,
        duration_us: now_us() - start,
    }
}

// ── Stage 3: Semantic Analysis ──

fn run_stage3(text: &str) -> StageResult {
    let start = now_us();
    let mut matches = Vec::new();
    let mut max_score: u32 = 0;
    let lower = text.to_lowercase();

    // Intent classification heuristics (pre-compiled)
    struct SemanticPattern {
        name: &'static str,
        regex: Regex,
        score: u32,
        severity: &'static str,
    }
    static SEMANTIC_PATTERNS: Lazy<Vec<SemanticPattern>> = Lazy::new(|| {
        let defs: Vec<(&str, &str, u32, &str)> = vec![
            (
                "data_theft",
                r"(?is)(steal|exfiltrate|extract|dump|harvest|scrape)\s+.*(data|credentials|secrets|tokens|keys|passwords|information)",
                90,
                "critical",
            ),
            (
                "system_compromise",
                r"(?is)(compromise|hack|exploit|penetrate|attack|breach)\s+.*(system|server|network|database|infrastructure)",
                90,
                "critical",
            ),
            (
                "persistence",
                r"(?is)(install|create|add|set\s+up)\s+.*(backdoor|trojan|rootkit|persistent\s+access|reverse\s+shell|c2|beacon)",
                95,
                "critical",
            ),
            (
                "reconnaissance",
                r"(?is)(enumerate|scan|discover|map|fingerprint)\s+.*(network|ports|services|users|hosts|infrastructure)",
                60,
                "medium",
            ),
            (
                "social_engineering",
                r"(?is)(phishing|impersonate|social\s+engineer|deceive|manipulate)\s+.*(users?|employees?|targets?|victims?)",
                85,
                "high",
            ),
            (
                "denial_of_service",
                r"(?is)(dos|ddos|flood|overwhelm|crash|exhaust)\s+.*(server|service|api|endpoint|resource)",
                80,
                "high",
            ),
        ];
        defs.into_iter()
            .filter_map(|(name, pat, score, severity)| {
                Regex::new(pat).ok().map(|re| SemanticPattern {
                    name,
                    regex: re,
                    score,
                    severity,
                })
            })
            .collect()
    });

    // ponytail: these are intent heuristics, not an NLP classifier. Restrict
    // them to directive-shaped clauses so incident reports and defensive
    // documentation do not become signed accusations. Expand the short prefix
    // list only when a measured phrasing needs it.
    fn is_directive_clause(text: &str, verb_start: usize) -> bool {
        let prefix = text[..verb_start]
            .rsplit(['.', '!', '?', ';', ':', '\n'])
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(['"', '\'', '\\', '{', '[', ','])
            .trim()
            .to_ascii_lowercase();
        matches!(
            prefix.as_str(),
            "" | "please"
                | "then"
                | "now"
                | "please then"
                | "can you"
                | "could you"
                | "would you"
                | "will you"
                | "you should"
                | "you must"
                | "we should"
                | "we must"
                | "i want you to"
                | "i need you to"
                | "i will"
                | "let's"
                | "help me"
                | "teach me to"
                | "how do i"
                | "how can i"
        )
    }

    for sp in SEMANTIC_PATTERNS.iter() {
        if let Some(m) = sp
            .regex
            .find_iter(text)
            .find(|m| is_directive_clause(text, m.start()))
        {
            let matched = truncate_on_char_boundary(m.as_str(), 100);
            matches.push(PatternMatch {
                pattern_name: sp.name.to_string(),
                severity: sp.severity.to_string(),
                matched_text: matched.to_string(),
                category: "semantic".into(),
            });
            max_score = max_score.max(sp.score);
        }
    }

    // Context-switching detection (e.g., "ignore previous... now do X")
    let segments: Vec<&str> = text.split('.').collect();
    let mut has_override = false;
    let mut has_dangerous_follow = false;

    for seg in &segments {
        let seg_lower = seg.to_lowercase();
        if seg_lower.contains("ignore")
            || seg_lower.contains("forget")
            || seg_lower.contains("disregard")
        {
            has_override = true;
        }
        if has_override
            && (seg_lower.contains("instead")
                || seg_lower.contains("now")
                || seg_lower.contains("actually"))
        {
            has_dangerous_follow = true;
        }
    }

    if has_override && has_dangerous_follow {
        let score = 85;
        matches.push(PatternMatch {
            pattern_name: "context_switch_attack".into(),
            severity: "critical".into(),
            matched_text: "instruction override followed by redirect".into(),
            category: "semantic".into(),
        });
        max_score = max_score.max(score);
    }

    // Payload-as-data detection (instructions hidden in what looks like data)
    if lower.contains("ignore")
        && (lower.contains("json") || lower.contains("xml") || lower.contains("csv"))
    {
        let score = 70;
        matches.push(PatternMatch {
            pattern_name: "payload_instruction_hiding".into(),
            severity: "high".into(),
            matched_text: "instructions embedded in data format context".into(),
            category: "semantic".into(),
        });
        max_score = max_score.max(score);
    }

    let triggered = !matches.is_empty();
    StageResult {
        stage: 3,
        name: "semantic_analysis".into(),
        triggered,
        score: max_score,
        matches,
        duration_us: now_us() - start,
    }
}

// ── Main Firewall ──

pub fn scan_prompt(text: &str) -> FirewallResult {
    let normalized = normalize_compat_ascii(text);
    let mut stage_results = Vec::new();

    // Stage 1: always runs
    let s1 = run_stage1(&normalized);
    let s1_triggered = s1.triggered;
    let s1_score = s1.score;
    stage_results.push(s1);

    // Stage 2: always runs (cheap structural check)
    let s2 = run_stage2(text);
    let s2_triggered = s2.triggered;
    let s2_score = s2.score;
    stage_results.push(s2);

    // Stage 3 must run independently: using stages 1-2 as a gate made every
    // semantic-only attack invisible by construction.
    let s3 = run_stage3(&normalized);
    let s3_triggered = s3.triggered;
    let s3_score = s3.score;
    stage_results.push(s3);

    // Composite score: max of all stages with slight boost for multi-stage hits
    let mut risk_score = s1_score.max(s2_score).max(s3_score);
    let stages_triggered = [s1_triggered, s2_triggered, s3_triggered]
        .iter()
        .filter(|&&x| x)
        .count();
    if stages_triggered >= 2 {
        risk_score = (risk_score + 10).min(100);
    }
    if stages_triggered == 3 {
        risk_score = (risk_score + 5).min(100);
    }

    let blocked = risk_score >= 75;

    let summary = if blocked {
        let mut categories: Vec<String> = stage_results
            .iter()
            .flat_map(|s| s.matches.iter().map(|m| m.category.clone()))
            .collect();
        categories.sort();
        categories.dedup();
        format!(
            "BLOCKED: injection detected (score={}, categories: {})",
            risk_score,
            categories.join(", ")
        )
    } else if risk_score > 0 {
        format!("FLAGGED: potential injection (score={})", risk_score)
    } else {
        "CLEAN: no injection detected".into()
    };

    // Update stats
    {
        let mut stats = STATS.lock().unwrap_or_else(|e| e.into_inner());
        stats.total_scanned += 1;
        if blocked {
            stats.total_blocked += 1;
        }
        if s1_triggered {
            stats.stage1_catches += 1;
        }
        if s2_triggered {
            stats.stage2_catches += 1;
        }
        if s3_score > 0 {
            stats.stage3_catches += 1;
        }
    }

    FirewallResult {
        blocked,
        risk_score,
        stages_run: 3,
        stage_results,
        summary,
        timestamp: now_ms(),
    }
}

/// Quick check for use in the pipeline, returns (blocked, score)
pub fn quick_scan(text: &str) -> (bool, u32) {
    let result = scan_prompt(text);
    (result.blocked, result.risk_score)
}

#[cfg(test)]
mod char_boundary_tests {
    use super::*;

    #[test]
    fn truncate_snaps_down_to_char_boundary() {
        // "é" is two bytes (0xC3 0xA9). Capping at 1 byte must snap to 0, not
        // split the codepoint.
        assert_eq!(truncate_on_char_boundary("é", 1), "");
        assert_eq!(truncate_on_char_boundary("aé", 2), "a");
        assert_eq!(truncate_on_char_boundary("abc", 2), "ab");
        assert_eq!(truncate_on_char_boundary("abc", 10), "abc");
        assert_eq!(truncate_on_char_boundary("", 5), "");
    }

    #[test]
    fn scan_prompt_does_not_panic_on_multibyte_straddling_the_caps() {
        // Pre-fix, run_stage1 / run_stage3 sliced `&text[start..start+80|100]`,
        // which panicked when a multi-byte char straddled the cap. This payload
        // matches a Stage-1 signature (hypothetical_framing → execute) so Stage 3
        // also runs (steal … data), with multi-byte chars filling both match
        // spans so the 80- and 100-byte caps land mid-codepoint.
        let payload = format!(
            "hypothetically {} execute, then steal {} data",
            "é".repeat(60),
            "ü".repeat(60)
        );
        let result = scan_prompt(&payload);
        assert!(result.risk_score <= 100);
        assert!(result.stages_run >= 2);
        // Sanity: matched_text snippets are valid UTF-8 (they always are, but this
        // confirms the truncation produced real strings, not a panic-avoided empty).
        for stage in &result.stage_results {
            for m in &stage.matches {
                assert!(m.matched_text.chars().count() <= m.matched_text.len());
            }
        }
    }
}
