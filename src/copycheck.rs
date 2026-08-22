//! Deterministic exact and near-copy checks with stable source byte ranges.
//!
//! Callers must treat [`scan_near_copy`](crate::copycheck::scan_near_copy) errors as blockers
//! because bounded scans fail closed.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::context::ByteRange;

const MAX_CANDIDATE_VERIFICATIONS: usize = 100_000;
const MAX_NGRAM_WINDOW_CLASSES: usize = 20_000;
const MAX_NGRAM_SIGNATURE_ITEMS: usize = 4_000_000;

#[derive(Clone)]
pub struct AllowedSource {
    pub source_id: String,
    text: String,
    exempt_ranges: Vec<ByteRange>,
}

impl AllowedSource {
    pub fn plain(source_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            text: text.into(),
            exempt_ranges: Vec::new(),
        }
    }

    pub fn declared_quote(source_id: impl Into<String>, text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            source_id: source_id.into(),
            exempt_ranges: vec![ByteRange::new(0, text.len())],
            text,
        }
    }

    pub fn with_declared_ranges(
        source_id: impl Into<String>,
        text: impl Into<String>,
        exempt_ranges: Vec<ByteRange>,
    ) -> Self {
        let text = text.into();
        Self {
            source_id: source_id.into(),
            exempt_ranges: exempt_ranges
                .into_iter()
                .filter(|range| range.is_valid_for(&text))
                .collect(),
            text,
        }
    }
}

impl fmt::Debug for AllowedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowedSource")
            .field("source_id", &self.source_id)
            .field("exempt_ranges", &self.exempt_ranges)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyPolicy {
    pub exact_cjk_graphemes: usize,
    pub exact_words: usize,
    pub ngram_size: usize,
    pub ngram_cjk_window: usize,
    pub ngram_word_window: usize,
    pub ngram_overlap_percent: u8,
}

impl Default for CopyPolicy {
    fn default() -> Self {
        Self {
            exact_cjk_graphemes: 80,
            exact_words: 40,
            ngram_size: 8,
            ngram_cjk_window: 160,
            ngram_word_window: 80,
            ngram_overlap_percent: 85,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CopyRule {
    ContiguousCjk,
    ContiguousWords,
    NgramOverlap,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyFinding {
    pub source_id: String,
    pub manuscript_range: ByteRange,
    pub source_range: ByteRange,
    pub rule: CopyRule,
    pub score_percent: u8,
    pub blocking: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyScanLimit {
    CandidateVerifications,
    NgramWindowClasses,
    NgramSignatureItems,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyScanError {
    InvalidPolicy(String),
    BudgetExceeded {
        limit: CopyScanLimit,
        maximum: usize,
    },
}

impl fmt::Display for CopyScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(message) => formatter.write_str(message),
            Self::BudgetExceeded { limit, maximum } => write!(
                formatter,
                "near-copy scan exceeded its fail-closed {limit:?} budget of {maximum}"
            ),
        }
    }
}

impl std::error::Error for CopyScanError {}

/// Scans deterministic witnesses, returning at most one non-exempt blocker per source and rule.
///
/// A scan-budget error is a blocker: callers must stop rather than treating it as no copy.
pub fn scan_near_copy(
    manuscript: &str,
    sources: &[AllowedSource],
    policy: &CopyPolicy,
) -> Result<Vec<CopyFinding>, CopyScanError> {
    validate_policy(policy)?;
    let manuscript = NormalizedText::from_text(manuscript);
    let mut ordered_sources = sources.iter().enumerate().collect::<Vec<_>>();
    ordered_sources.sort_by(|(left_index, left), (right_index, right)| {
        (left.source_id.as_str(), left_index).cmp(&(right.source_id.as_str(), right_index))
    });

    let mut findings = Vec::new();
    let mut budget = ScanBudget::default();
    for (_, source) in ordered_sources {
        let normalized = NormalizedText::from_text(&source.text);
        let exact_cjk = scan_exact_witness(
            &manuscript.cjk_runs,
            &normalized.cjk_runs,
            source,
            policy.exact_cjk_graphemes,
            CopyRule::ContiguousCjk,
        );
        let has_exact_cjk = exact_cjk.is_some();
        if let Some(finding) = exact_cjk {
            findings.push(finding);
        }
        let exact_words = scan_exact_witness(
            &manuscript.word_runs,
            &normalized.word_runs,
            source,
            policy.exact_words,
            CopyRule::ContiguousWords,
        );
        let has_exact_words = exact_words.is_some();
        if let Some(finding) = exact_words {
            findings.push(finding);
        }
        if !has_exact_cjk && !has_exact_words {
            if let Some(finding) =
                scan_character_ngram_witness(&manuscript, &normalized, source, policy, &mut budget)?
            {
                findings.push(finding);
            } else if let Some(finding) =
                scan_word_ngram_witness(&manuscript, &normalized, source, policy, &mut budget)?
            {
                findings.push(finding);
            }
        }
    }
    findings.sort_by(|left, right| {
        (
            left.source_id.as_str(),
            left.manuscript_range.start,
            left.manuscript_range.end,
            left.source_range.start,
            left.source_range.end,
            left.rule,
        )
            .cmp(&(
                right.source_id.as_str(),
                right.manuscript_range.start,
                right.manuscript_range.end,
                right.source_range.start,
                right.source_range.end,
                right.rule,
            ))
    });
    Ok(findings)
}

fn validate_policy(policy: &CopyPolicy) -> Result<(), CopyScanError> {
    if policy.exact_cjk_graphemes == 0 || policy.exact_words == 0 || policy.ngram_size == 0 {
        return Err(CopyScanError::InvalidPolicy(
            "near-copy thresholds must be greater than zero".into(),
        ));
    }
    if policy.ngram_cjk_window < policy.ngram_size || policy.ngram_word_window == 0 {
        return Err(CopyScanError::InvalidPolicy(
            "near-copy windows must contain at least one complete 8-gram candidate".into(),
        ));
    }
    if policy.ngram_overlap_percent > 100 {
        return Err(CopyScanError::InvalidPolicy(
            "near-copy overlap percentage cannot exceed 100".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct Token {
    normalized: String,
    range: ByteRange,
}

struct NormalizedText {
    cjk_runs: Vec<Vec<Token>>,
    word_runs: Vec<Vec<Token>>,
    word_char_runs: Vec<WordCharRun>,
    character_runs: Vec<CharacterRun>,
}

struct WordCharRun {
    tokens: Vec<Token>,
    word_starts: Vec<usize>,
}

struct CharacterRun {
    tokens: Vec<Token>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct TokenWindow {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct IndexedWindow {
    run: usize,
    window: TokenWindow,
}

impl NormalizedText {
    fn from_text(text: &str) -> Self {
        let mut cjk_runs = Vec::new();
        let mut cjk = Vec::new();
        let mut word_runs = Vec::new();
        let mut words = Vec::new();
        let mut word: Option<Token> = None;
        let mut word_char_runs = Vec::new();
        let mut word_chars = Vec::new();
        let mut word_starts = Vec::new();
        let mut character_runs = Vec::new();
        let mut characters = Vec::new();

        for (start, grapheme) in text.grapheme_indices(true) {
            let end = start + grapheme.len();
            let normalized = grapheme
                .nfkc()
                .flat_map(char::to_lowercase)
                .filter(|character| !is_default_ignorable(*character))
                .collect::<String>();
            if normalized.is_empty() {
                continue;
            }
            if normalized.chars().all(is_spacing_or_punctuation) {
                if word.is_some() {
                    finish_word(&mut word, &mut words);
                    word_chars.push(Token {
                        normalized: " ".into(),
                        range: ByteRange::new(start, end),
                    });
                }
                continue;
            }

            let range = ByteRange::new(start, end);
            let pieces = normalized
                .graphemes(true)
                .filter(|piece| !piece.chars().all(is_spacing_or_punctuation))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            for piece in &pieces {
                characters.push(Token {
                    normalized: piece.clone(),
                    range,
                });
            }

            let cjk_pieces = pieces
                .iter()
                .filter(|piece| piece.chars().any(is_cjk))
                .cloned()
                .collect::<Vec<_>>();
            if !cjk_pieces.is_empty() {
                finish_word(&mut word, &mut words);
                finish_word_run(&mut words, &mut word_runs);
                finish_word_chars(&mut word_chars, &mut word_starts, &mut word_char_runs);
                cjk.extend(
                    cjk_pieces
                        .into_iter()
                        .map(|normalized| Token { normalized, range }),
                );
                continue;
            }

            if !cjk.is_empty() {
                cjk_runs.push(std::mem::take(&mut cjk));
            }
            if normalized.chars().all(char::is_alphanumeric) {
                if word.is_none() {
                    word_starts.push(word_chars.len());
                }
                for piece in pieces {
                    word_chars.push(Token {
                        normalized: piece,
                        range,
                    });
                }
                match &mut word {
                    Some(current) => {
                        current.normalized.push_str(&normalized);
                        current.range.end = end;
                    }
                    None => {
                        word = Some(Token { normalized, range });
                    }
                }
            } else {
                for piece in pieces {
                    word_chars.push(Token {
                        normalized: piece,
                        range,
                    });
                }
            }
        }
        finish_word(&mut word, &mut words);
        finish_word_run(&mut words, &mut word_runs);
        finish_word_chars(&mut word_chars, &mut word_starts, &mut word_char_runs);
        if !cjk.is_empty() {
            cjk_runs.push(cjk);
        }
        if !characters.is_empty() {
            character_runs.push(CharacterRun { tokens: characters });
        }
        Self {
            cjk_runs,
            word_runs,
            word_char_runs,
            character_runs,
        }
    }
}

fn finish_word(word: &mut Option<Token>, words: &mut Vec<Token>) {
    if let Some(word) = word.take() {
        words.push(word);
    }
}

fn finish_word_run(words: &mut Vec<Token>, runs: &mut Vec<Vec<Token>>) {
    if !words.is_empty() {
        runs.push(std::mem::take(words));
    }
}

fn finish_word_chars(chars: &mut Vec<Token>, starts: &mut Vec<usize>, runs: &mut Vec<WordCharRun>) {
    if !chars.is_empty() {
        runs.push(WordCharRun {
            tokens: std::mem::take(chars),
            word_starts: std::mem::take(starts),
        });
    }
}

fn is_spacing_or_punctuation(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            get_general_category(character),
            GeneralCategory::ConnectorPunctuation
                | GeneralCategory::DashPunctuation
                | GeneralCategory::ClosePunctuation
                | GeneralCategory::FinalPunctuation
                | GeneralCategory::InitialPunctuation
                | GeneralCategory::OtherPunctuation
                | GeneralCategory::OpenPunctuation
                | GeneralCategory::Format
        )
}

fn is_default_ignorable(character: char) -> bool {
    matches!(get_general_category(character), GeneralCategory::Format)
        || matches!(
            character as u32,
            0x00ad
                | 0x034f
                | 0x115f..=0x1160
                | 0x17b4..=0x17b5
                | 0x180b..=0x180d
                | 0x180e
                | 0x3164
                | 0xfe00..=0xfe0f
                | 0xffa0
                | 0xfff0..=0xfff8
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0000..=0xe0fff
        )
}

fn is_cjk(character: char) -> bool {
    matches!(
        character as u32,
        0x3040..=0x30ff
            | 0x1100..=0x11ff
            | 0x3100..=0x318f
            | 0x3400..=0x4dbf
            | 0x4e00..=0x9fff
            | 0xa960..=0xa97f
            | 0xac00..=0xd7ff
            | 0xf900..=0xfaff
            | 0xff66..=0xff9d
            | 0x20000..=0x323af
    )
}

type ExactFingerprint = (u64, u64);

#[derive(Clone, Copy)]
struct ExactWitness {
    run: usize,
    start: usize,
}

fn scan_exact_witness(
    manuscript_runs: &[Vec<Token>],
    source_runs: &[Vec<Token>],
    source: &AllowedSource,
    threshold: usize,
    rule: CopyRule,
) -> Option<CopyFinding> {
    let mut index = BTreeMap::<ExactFingerprint, ExactWitness>::new();
    for (run_index, source_run) in source_runs.iter().enumerate() {
        for (start, fingerprint) in exact_fingerprints(source_run, threshold)
            .into_iter()
            .enumerate()
        {
            let source_range = token_range(source_run, start, start + threshold);
            if is_exempt(source, source_range) {
                continue;
            }
            index.entry(fingerprint).or_insert(ExactWitness {
                run: run_index,
                start,
            });
        }
    }
    for manuscript_run in manuscript_runs.iter().filter(|run| run.len() >= threshold) {
        for (start, fingerprint) in exact_fingerprints(manuscript_run, threshold)
            .into_iter()
            .enumerate()
        {
            let Some(witness) = index.get(&fingerprint) else {
                continue;
            };
            let source_run = &source_runs[witness.run];
            if same_tokens(
                &manuscript_run[start..start + threshold],
                &source_run[witness.start..witness.start + threshold],
            ) {
                return Some(CopyFinding {
                    source_id: source.source_id.clone(),
                    manuscript_range: token_range(manuscript_run, start, start + threshold),
                    source_range: token_range(source_run, witness.start, witness.start + threshold),
                    rule,
                    score_percent: 100,
                    blocking: true,
                });
            }
        }
    }
    None
}

fn exact_fingerprints(tokens: &[Token], width: usize) -> Vec<ExactFingerprint> {
    if tokens.len() < width {
        return Vec::new();
    }
    let first = rolling_hashes(tokens, width, 1_000_000_007, stable_hash);
    let second = rolling_hashes(tokens, width, 1_000_000_021, stable_hash_alt);
    first.into_iter().zip(second).collect()
}

fn rolling_hashes(
    tokens: &[Token],
    width: usize,
    base: u64,
    hash_token: fn(&str) -> u64,
) -> Vec<u64> {
    let values = tokens
        .iter()
        .map(|token| hash_token(&token.normalized))
        .collect::<Vec<_>>();
    let mut factor = 1_u64;
    for _ in 1..width {
        factor = factor.wrapping_mul(base);
    }
    let mut hash = 0_u64;
    for &value in &values[..width] {
        hash = hash.wrapping_mul(base).wrapping_add(value);
    }
    let mut result = vec![hash];
    for index in width..values.len() {
        hash = hash
            .wrapping_sub(values[index - width].wrapping_mul(factor))
            .wrapping_mul(base)
            .wrapping_add(values[index]);
        result.push(hash);
    }
    result
}

fn stable_hash(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn stable_hash_alt(value: &str) -> u64 {
    value.bytes().fold(0x9e37_79b9_7f4a_7c15_u64, |hash, byte| {
        (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

type NgramFingerprint = [u8; 32];

struct NgramClass {
    run: usize,
    window: TokenWindow,
    signature: Vec<NgramFingerprint>,
}

#[derive(Default)]
struct ScanBudget {
    verifications: usize,
}

impl ScanBudget {
    fn charge(&mut self) -> Result<(), CopyScanError> {
        if self.verifications == MAX_CANDIDATE_VERIFICATIONS {
            return Err(CopyScanError::BudgetExceeded {
                limit: CopyScanLimit::CandidateVerifications,
                maximum: MAX_CANDIDATE_VERIFICATIONS,
            });
        }
        self.verifications += 1;
        Ok(())
    }
}

fn scan_character_ngram_witness(
    manuscript: &NormalizedText,
    source_text: &NormalizedText,
    source: &AllowedSource,
    policy: &CopyPolicy,
    budget: &mut ScanBudget,
) -> Result<Option<CopyFinding>, CopyScanError> {
    let manuscript_runs = manuscript
        .character_runs
        .iter()
        .filter(|run| run.tokens.len() >= policy.ngram_cjk_window)
        .map(|run| run.tokens.as_slice())
        .collect::<Vec<_>>();
    let source_runs = source_text
        .character_runs
        .iter()
        .filter(|run| run.tokens.len() >= policy.ngram_cjk_window)
        .map(|run| run.tokens.as_slice())
        .collect::<Vec<_>>();
    let manuscript_window_count = fixed_window_count(&manuscript_runs, policy.ngram_cjk_window);
    let source_window_count = fixed_window_count(&source_runs, policy.ngram_cjk_window);
    if manuscript_window_count == 0 || source_window_count == 0 {
        return Ok(None);
    }
    ensure_window_class_budget(manuscript_window_count)?;
    let manuscript_windows = fixed_windows(&manuscript_runs, policy.ngram_cjk_window);
    let source_windows = fixed_windows(&source_runs, policy.ngram_cjk_window);
    scan_ngram_witness(
        &manuscript_runs,
        &manuscript_windows,
        &source_runs,
        &source_windows,
        source,
        policy.ngram_size,
        policy.ngram_overlap_percent,
        budget,
    )
}

fn scan_word_ngram_witness(
    manuscript: &NormalizedText,
    source_text: &NormalizedText,
    source: &AllowedSource,
    policy: &CopyPolicy,
    budget: &mut ScanBudget,
) -> Result<Option<CopyFinding>, CopyScanError> {
    let manuscript_runs = manuscript
        .word_char_runs
        .iter()
        .map(|run| run.tokens.as_slice())
        .collect::<Vec<_>>();
    let source_runs = source_text
        .word_char_runs
        .iter()
        .map(|run| run.tokens.as_slice())
        .collect::<Vec<_>>();
    let manuscript_window_count =
        word_window_count(&manuscript.word_char_runs, policy.ngram_word_window);
    let source_window_count =
        word_window_count(&source_text.word_char_runs, policy.ngram_word_window);
    if manuscript_window_count == 0 || source_window_count == 0 {
        return Ok(None);
    }
    ensure_window_class_budget(manuscript_window_count)?;
    let manuscript_windows =
        word_windows_for_runs(&manuscript.word_char_runs, policy.ngram_word_window);
    let source_windows =
        word_windows_for_runs(&source_text.word_char_runs, policy.ngram_word_window);
    scan_ngram_witness(
        &manuscript_runs,
        &manuscript_windows,
        &source_runs,
        &source_windows,
        source,
        policy.ngram_size,
        policy.ngram_overlap_percent,
        budget,
    )
}

fn ensure_window_class_budget(window_count: usize) -> Result<(), CopyScanError> {
    if window_count > MAX_NGRAM_WINDOW_CLASSES {
        return Err(CopyScanError::BudgetExceeded {
            limit: CopyScanLimit::NgramWindowClasses,
            maximum: MAX_NGRAM_WINDOW_CLASSES,
        });
    }
    Ok(())
}

fn fixed_window_count(runs: &[&[Token]], width: usize) -> usize {
    runs.iter().fold(0_usize, |count, tokens| {
        let windows = if tokens.len() >= width {
            tokens.len() - width + 1
        } else {
            0
        };
        count.saturating_add(windows)
    })
}

fn fixed_windows(runs: &[&[Token]], width: usize) -> Vec<IndexedWindow> {
    let mut windows = Vec::new();
    for (run, tokens) in runs.iter().enumerate() {
        for start in 0..=tokens.len() - width {
            windows.push(IndexedWindow {
                run,
                window: TokenWindow {
                    start,
                    end: start + width,
                },
            });
        }
    }
    windows
}

fn word_window_count(runs: &[WordCharRun], word_count: usize) -> usize {
    runs.iter().fold(0_usize, |count, run| {
        let windows = if run.word_starts.len() >= word_count {
            run.word_starts.len() - word_count + 1
        } else {
            0
        };
        count.saturating_add(windows)
    })
}

fn word_windows_for_runs(runs: &[WordCharRun], word_count: usize) -> Vec<IndexedWindow> {
    let mut windows = Vec::new();
    for (run, value) in runs.iter().enumerate() {
        if value.word_starts.len() < word_count {
            continue;
        }
        for word_start in 0..=value.word_starts.len() - word_count {
            windows.push(IndexedWindow {
                run,
                window: TokenWindow {
                    start: value.word_starts[word_start],
                    end: word_window_end(value, word_start, word_count),
                },
            });
        }
    }
    windows
}

fn scan_ngram_witness(
    manuscript_runs: &[&[Token]],
    manuscript_windows: &[IndexedWindow],
    source_runs: &[&[Token]],
    source_windows: &[IndexedWindow],
    source: &AllowedSource,
    ngram_size: usize,
    overlap_percent: u8,
    budget: &mut ScanBudget,
) -> Result<Option<CopyFinding>, CopyScanError> {
    let classes = build_ngram_classes(manuscript_runs, manuscript_windows, ngram_size)?;
    if classes.is_empty() {
        return Ok(None);
    }
    if overlap_percent == 0 {
        for window in source_windows {
            if window.window.end - window.window.start < ngram_size {
                continue;
            }
            let source_range = token_range(
                source_runs[window.run],
                window.window.start,
                window.window.end,
            );
            if !is_exempt(source, source_range) {
                let manuscript = &classes[0];
                return Ok(Some(CopyFinding {
                    source_id: source.source_id.clone(),
                    manuscript_range: token_range(
                        manuscript_runs[manuscript.run],
                        manuscript.window.start,
                        manuscript.window.end,
                    ),
                    source_range,
                    rule: CopyRule::NgramOverlap,
                    score_percent: 0,
                    blocking: true,
                }));
            }
        }
        return Ok(None);
    }

    let index = build_prefix_index(&classes, overlap_percent);
    let mut seen = vec![0_u64; classes.len()];
    let mut epoch = 0_u64;
    let mut current_run = None;
    let mut current_window = None;
    let mut source_hashes = Vec::new();
    let mut source_counts = BTreeMap::<NgramFingerprint, usize>::new();

    for source_window in source_windows {
        if source_window.window.end - source_window.window.start < ngram_size {
            continue;
        }
        if current_run != Some(source_window.run) {
            current_run = Some(source_window.run);
            current_window = None;
            source_hashes = ngram_fingerprints(source_runs[source_window.run], ngram_size);
            source_counts.clear();
        }
        match current_window {
            Some(previous) => advance_window_counts(
                &mut source_counts,
                &source_hashes,
                previous,
                source_window.window,
                ngram_size,
            ),
            None => {
                source_counts = window_counts(&source_hashes, source_window.window, ngram_size);
            }
        }
        current_window = Some(source_window.window);

        let source_range = token_range(
            source_runs[source_window.run],
            source_window.window.start,
            source_window.window.end,
        );
        if is_exempt(source, source_range) {
            continue;
        }
        epoch = epoch.wrapping_add(1);
        if epoch == 0 {
            seen.fill(0);
            epoch = 1;
        }
        let source_count = ngram_count(source_window.window, ngram_size);
        let prefix = multiset_prefix(&source_counts, prefix_length(source_count, overlap_percent));
        for key in prefix {
            let Some(candidates) = index.get(&key) else {
                continue;
            };
            for &candidate in candidates {
                if seen[candidate] == epoch {
                    continue;
                }
                seen[candidate] = epoch;
                budget.charge()?;
                let manuscript = &classes[candidate];
                let denominator = source_count.max(manuscript.signature.len());
                let required = required_overlap(denominator, overlap_percent);
                let shared = multiset_overlap(&source_counts, &manuscript.signature);
                if shared < required {
                    continue;
                }
                return Ok(Some(CopyFinding {
                    source_id: source.source_id.clone(),
                    manuscript_range: token_range(
                        manuscript_runs[manuscript.run],
                        manuscript.window.start,
                        manuscript.window.end,
                    ),
                    source_range,
                    rule: CopyRule::NgramOverlap,
                    score_percent: ((shared * 100) / denominator) as u8,
                    blocking: true,
                }));
            }
        }
    }
    Ok(None)
}

fn build_ngram_classes(
    runs: &[&[Token]],
    windows: &[IndexedWindow],
    ngram_size: usize,
) -> Result<Vec<NgramClass>, CopyScanError> {
    let signature_items = windows.iter().try_fold(0_usize, |count, indexed| {
        count
            .checked_add(ngram_count(indexed.window, ngram_size))
            .ok_or(CopyScanError::BudgetExceeded {
                limit: CopyScanLimit::NgramSignatureItems,
                maximum: MAX_NGRAM_SIGNATURE_ITEMS,
            })
    })?;
    if signature_items > MAX_NGRAM_SIGNATURE_ITEMS {
        return Err(CopyScanError::BudgetExceeded {
            limit: CopyScanLimit::NgramSignatureItems,
            maximum: MAX_NGRAM_SIGNATURE_ITEMS,
        });
    }
    let hashes = runs
        .iter()
        .map(|run| ngram_fingerprints(run, ngram_size))
        .collect::<Vec<_>>();
    Ok(windows
        .iter()
        .filter_map(|indexed| {
            let count = ngram_count(indexed.window, ngram_size);
            (count > 0).then(|| {
                let end = indexed.window.start + count;
                let mut signature = hashes[indexed.run][indexed.window.start..end].to_vec();
                signature.sort_unstable();
                NgramClass {
                    run: indexed.run,
                    window: indexed.window,
                    signature,
                }
            })
        })
        .collect())
}

fn build_prefix_index(
    classes: &[NgramClass],
    overlap_percent: u8,
) -> BTreeMap<NgramFingerprint, Vec<usize>> {
    let mut index = BTreeMap::<NgramFingerprint, Vec<usize>>::new();
    for (class_index, class) in classes.iter().enumerate() {
        let mut prior = None;
        for key in class
            .signature
            .iter()
            .take(prefix_length(class.signature.len(), overlap_percent))
        {
            if prior == Some(key) {
                continue;
            }
            index.entry(*key).or_default().push(class_index);
            prior = Some(key);
        }
    }
    index
}

fn ngram_fingerprints(tokens: &[Token], width: usize) -> Vec<NgramFingerprint> {
    if tokens.len() < width {
        return Vec::new();
    }
    (0..=tokens.len() - width)
        .map(|start| {
            let mut hasher = Sha256::new();
            hasher.update(b"phemius-ngram-v1");
            for token in &tokens[start..start + width] {
                hasher.update((token.normalized.len() as u64).to_be_bytes());
                hasher.update(token.normalized.as_bytes());
            }
            hasher.finalize().into()
        })
        .collect()
}

fn window_counts(
    hashes: &[NgramFingerprint],
    window: TokenWindow,
    ngram_size: usize,
) -> BTreeMap<NgramFingerprint, usize> {
    let count = ngram_count(window, ngram_size);
    let mut result = BTreeMap::new();
    for hash in &hashes[window.start..window.start + count] {
        *result.entry(*hash).or_default() += 1;
    }
    result
}

fn advance_window_counts(
    counts: &mut BTreeMap<NgramFingerprint, usize>,
    hashes: &[NgramFingerprint],
    previous: TokenWindow,
    next: TokenWindow,
    ngram_size: usize,
) {
    let previous_end = previous.start + ngram_count(previous, ngram_size);
    let next_end = next.start + ngram_count(next, ngram_size);
    debug_assert!(previous.start <= next.start && previous_end <= next_end);
    for hash in &hashes[previous.start..next.start] {
        let remove = counts
            .get_mut(hash)
            .expect("sliding multiset must contain removed n-gram");
        *remove -= 1;
        if *remove == 0 {
            counts.remove(hash);
        }
    }
    for hash in &hashes[previous_end..next_end] {
        *counts.entry(*hash).or_default() += 1;
    }
}

fn ngram_count(window: TokenWindow, ngram_size: usize) -> usize {
    (window.end - window.start)
        .checked_sub(ngram_size)
        .map_or(0, |width| width + 1)
}

fn required_overlap(count: usize, overlap_percent: u8) -> usize {
    (count * overlap_percent as usize).div_ceil(100)
}

fn prefix_length(count: usize, overlap_percent: u8) -> usize {
    count
        .saturating_sub(required_overlap(count, overlap_percent))
        .saturating_add(1)
        .min(count)
}

fn multiset_prefix(
    counts: &BTreeMap<NgramFingerprint, usize>,
    needed: usize,
) -> Vec<NgramFingerprint> {
    let mut result = Vec::with_capacity(needed);
    for (key, count) in counts {
        for _ in 0..*count {
            if result.len() == needed {
                return result;
            }
            result.push(*key);
        }
    }
    result
}

fn multiset_overlap(
    counts: &BTreeMap<NgramFingerprint, usize>,
    sorted_signature: &[NgramFingerprint],
) -> usize {
    let mut shared = 0;
    let mut start = 0;
    while start < sorted_signature.len() {
        let key = sorted_signature[start];
        let mut end = start + 1;
        while end < sorted_signature.len() && sorted_signature[end] == key {
            end += 1;
        }
        shared += counts
            .get(&key)
            .copied()
            .unwrap_or_default()
            .min(end - start);
        start = end;
    }
    shared
}

fn word_window_end(run: &WordCharRun, word_start: usize, word_count: usize) -> usize {
    let next_word = word_start + word_count;
    if next_word == run.word_starts.len() {
        run.tokens.len()
    } else {
        run.word_starts[next_word].saturating_sub(1)
    }
}

fn same_tokens(left: &[Token], right: &[Token]) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| left.normalized == right.normalized)
}

fn token_range(tokens: &[Token], start: usize, end: usize) -> ByteRange {
    ByteRange::new(tokens[start].range.start, tokens[end - 1].range.end)
}

fn is_exempt(source: &AllowedSource, range: ByteRange) -> bool {
    source
        .exempt_ranges
        .iter()
        .any(|exempt| exempt.start <= range.start && range.end <= exempt.end)
}
