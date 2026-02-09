//! Data masking engine for sensitive content before AI calls.

use crate::privacy::classifier::{DataCategory, SensitiveDataClassifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Masking strategy to apply for a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    Redact,
    Hash,
    Pseudonymize,
    Truncate,
    Generalize,
    Tokenize,
}

/// Mapping record from original range to replacement text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskMapping {
    pub category: DataCategory,
    pub original_range: (usize, usize),
    pub replacement: String,
}

/// Masked output container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskedText {
    pub text: String,
    pub mappings: Vec<MaskMapping>,
}

/// Masking engine with configurable per-category strategies.
#[derive(Debug, Clone)]
pub struct DataMasker {
    classifier: SensitiveDataClassifier,
    strategies: HashMap<DataCategory, MaskingStrategy>,
    token_store: HashMap<String, String>,
}

impl Default for DataMasker {
    fn default() -> Self {
        let mut strategies = HashMap::new();
        strategies.insert(DataCategory::Pii, MaskingStrategy::Redact);
        strategies.insert(DataCategory::Credential, MaskingStrategy::Tokenize);
        strategies.insert(DataCategory::Financial, MaskingStrategy::Hash);
        strategies.insert(DataCategory::Health, MaskingStrategy::Generalize);
        strategies.insert(DataCategory::Internal, MaskingStrategy::Pseudonymize);

        Self {
            classifier: SensitiveDataClassifier::with_default_patterns(),
            strategies,
            token_store: HashMap::new(),
        }
    }
}

impl DataMasker {
    /// Creates a masker with classifier and explicit strategy map.
    pub fn new(
        classifier: SensitiveDataClassifier,
        strategies: HashMap<DataCategory, MaskingStrategy>,
    ) -> Self {
        Self {
            classifier,
            strategies,
            token_store: HashMap::new(),
        }
    }

    /// Updates strategy for a category.
    pub fn set_strategy(&mut self, category: DataCategory, strategy: MaskingStrategy) {
        self.strategies.insert(category, strategy);
    }

    /// Applies masking to text and returns replacement mappings.
    pub fn mask(&mut self, text: &str) -> MaskedText {
        let mut output = text.to_string();
        let mut mappings = Vec::new();
        let mut matches = self.classifier.classify(text);
        matches.sort_by(|a, b| b.start.cmp(&a.start));

        for found in matches {
            let strategy = self
                .strategies
                .get(&found.category)
                .copied()
                .unwrap_or(MaskingStrategy::Redact);
            let source = &text[found.start..found.end];
            let replacement = self.apply_strategy(strategy, &found.category, source);

            output.replace_range(found.start..found.end, &replacement);
            mappings.push(MaskMapping {
                category: found.category,
                original_range: (found.start, found.end),
                replacement,
            });
        }

        mappings.reverse();
        MaskedText {
            text: output,
            mappings,
        }
    }

    /// Restores a tokenized value when the token exists in the store.
    pub fn resolve_token(&self, token: &str) -> Option<&str> {
        self.token_store.get(token).map(String::as_str)
    }

    fn apply_strategy(
        &mut self,
        strategy: MaskingStrategy,
        category: &DataCategory,
        value: &str,
    ) -> String {
        match strategy {
            MaskingStrategy::Redact => format!("[REDACTED:{}]", category.as_key()),
            MaskingStrategy::Hash => {
                let digest = Sha256::digest(value.as_bytes());
                format!("sha256:{}", hex::encode(&digest[..8]))
            }
            MaskingStrategy::Pseudonymize => {
                let digest = Sha256::digest(value.as_bytes());
                format!(
                    "PSEUDO_{}_{}",
                    category.as_key().replace(':', "_").to_ascii_uppercase(),
                    hex::encode(&digest[..4]).to_ascii_uppercase()
                )
            }
            MaskingStrategy::Truncate => truncate(value, 2, 2),
            MaskingStrategy::Generalize => format!("<{}>", category.as_key()),
            MaskingStrategy::Tokenize => {
                let token = format!("TOK_{}", self.token_store.len() + 1);
                self.token_store.insert(token.clone(), value.to_string());
                token
            }
        }
    }
}

fn truncate(value: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= head + tail {
        return "*".repeat(chars.len());
    }
    let start: String = chars.iter().take(head).collect();
    let end: String = chars.iter().skip(chars.len() - tail).collect();
    format!("{start}***{end}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_redacts_email() {
        let mut masker = DataMasker::default();
        let result = masker.mask("email admin@example.com");
        assert!(result.text.contains("[REDACTED:pii]"));
        assert!(!result.mappings.is_empty());
    }

    #[test]
    fn test_tokenization_is_reversible() {
        let mut masker = DataMasker::default();
        masker.set_strategy(DataCategory::Credential, MaskingStrategy::Tokenize);
        let result = masker.mask("api_key=supersecretvalue");
        let token = result
            .mappings
            .iter()
            .find(|m| m.category == DataCategory::Credential)
            .map(|m| m.replacement.clone())
            .expect("token mapping");
        assert!(masker.resolve_token(&token).is_some());
    }
}
