//! Document content extraction for knowledge base indexing.
//!
//! This module provides utilities for extracting plain text from various
//! document formats for embedding and indexing in the RAG system.
//!
//! # Supported Formats
//!
//! - **Markdown** (.md): Native support, converts to plain text
//! - **Plain Text** (.txt): Passed through directly
//! - **HTML** (.html): Basic tag stripping
//! - **PDF** (.pdf): Requires external parser (via `pdf` feature flag)
//!
//! # Example
//!
//! ```ignore
//! use tw_core::knowledge::extraction::{DocumentExtractor, DocumentFormat};
//!
//! let extractor = DocumentExtractor::new();
//! let text = extractor.extract_text(content, DocumentFormat::Markdown)?;
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for document extraction.
#[derive(Debug, Error)]
pub enum ExtractionError {
    /// Unsupported document format.
    #[error("Unsupported document format: {0}")]
    UnsupportedFormat(String),

    /// Failed to parse document.
    #[error("Failed to parse document: {0}")]
    ParseError(String),

    /// Document is empty or contains no extractable text.
    #[error("Document is empty or contains no extractable text")]
    EmptyDocument,

    /// Document exceeds maximum size limit.
    #[error("Document exceeds maximum size limit of {0} bytes")]
    TooLarge(usize),

    /// PDF extraction requires the pdf feature.
    #[error("PDF extraction requires the 'pdf' feature to be enabled")]
    PdfFeatureRequired,
}

/// Result type for extraction operations.
pub type ExtractionResult<T> = Result<T, ExtractionError>;

/// Supported document formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentFormat {
    /// Markdown format.
    Markdown,
    /// Plain text.
    PlainText,
    /// HTML format.
    Html,
    /// PDF format (requires feature).
    Pdf,
}

impl DocumentFormat {
    /// Detect format from file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "md" | "markdown" => Some(DocumentFormat::Markdown),
            "txt" | "text" => Some(DocumentFormat::PlainText),
            "html" | "htm" => Some(DocumentFormat::Html),
            "pdf" => Some(DocumentFormat::Pdf),
            _ => None,
        }
    }

    /// Detect format from MIME type.
    pub fn from_mime_type(mime: &str) -> Option<Self> {
        match mime {
            "text/markdown" | "text/x-markdown" => Some(DocumentFormat::Markdown),
            "text/plain" => Some(DocumentFormat::PlainText),
            "text/html" => Some(DocumentFormat::Html),
            "application/pdf" => Some(DocumentFormat::Pdf),
            _ => None,
        }
    }

    /// Get the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            DocumentFormat::Markdown => "md",
            DocumentFormat::PlainText => "txt",
            DocumentFormat::Html => "html",
            DocumentFormat::Pdf => "pdf",
        }
    }

    /// Get the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            DocumentFormat::Markdown => "text/markdown",
            DocumentFormat::PlainText => "text/plain",
            DocumentFormat::Html => "text/html",
            DocumentFormat::Pdf => "application/pdf",
        }
    }
}

/// Configuration for document extraction.
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// Maximum document size in bytes.
    pub max_size: usize,
    /// Whether to preserve code blocks in markdown.
    pub preserve_code_blocks: bool,
    /// Whether to extract text from links.
    pub include_link_text: bool,
    /// Minimum text length to consider valid.
    pub min_text_length: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            max_size: 10 * 1024 * 1024, // 10MB
            preserve_code_blocks: true,
            include_link_text: true,
            min_text_length: 10,
        }
    }
}

/// Document extractor for converting various formats to plain text.
pub struct DocumentExtractor {
    config: ExtractionConfig,
}

impl DocumentExtractor {
    /// Create a new document extractor with default configuration.
    pub fn new() -> Self {
        Self {
            config: ExtractionConfig::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: ExtractionConfig) -> Self {
        Self { config }
    }

    /// Extract plain text from document content.
    pub fn extract_text(&self, content: &str, format: DocumentFormat) -> ExtractionResult<String> {
        // Check size limit
        if content.len() > self.config.max_size {
            return Err(ExtractionError::TooLarge(self.config.max_size));
        }

        let text = match format {
            DocumentFormat::Markdown => self.extract_from_markdown(content)?,
            DocumentFormat::PlainText => content.to_string(),
            DocumentFormat::Html => self.extract_from_html(content)?,
            DocumentFormat::Pdf => return Err(ExtractionError::PdfFeatureRequired),
        };

        // Validate result
        let trimmed = text.trim();
        if trimmed.len() < self.config.min_text_length {
            return Err(ExtractionError::EmptyDocument);
        }

        Ok(trimmed.to_string())
    }

    /// Extract text from bytes with format detection.
    pub fn extract_text_auto(
        &self,
        content: &str,
        filename: Option<&str>,
        mime_type: Option<&str>,
    ) -> ExtractionResult<String> {
        // Try to detect format
        let format = mime_type
            .and_then(DocumentFormat::from_mime_type)
            .or_else(|| {
                filename.and_then(|f| {
                    f.rsplit('.')
                        .next()
                        .and_then(DocumentFormat::from_extension)
                })
            })
            .unwrap_or(DocumentFormat::PlainText);

        self.extract_text(content, format)
    }

    /// Extract text from markdown content.
    fn extract_from_markdown(&self, content: &str) -> ExtractionResult<String> {
        let mut result = String::new();
        let mut in_code_block = false;
        let mut code_block_content = String::new();

        for line in content.lines() {
            // Handle code block boundaries
            if line.starts_with("```") {
                if in_code_block {
                    // End of code block
                    if self.config.preserve_code_blocks && !code_block_content.is_empty() {
                        result.push_str("\n[Code Block]\n");
                        result.push_str(&code_block_content);
                        result.push('\n');
                    }
                    code_block_content.clear();
                }
                in_code_block = !in_code_block;
                continue;
            }

            if in_code_block {
                code_block_content.push_str(line);
                code_block_content.push('\n');
                continue;
            }

            // Process non-code content
            let processed = self.process_markdown_line(line);
            if !processed.is_empty() {
                result.push_str(&processed);
                result.push('\n');
            }
        }

        Ok(result)
    }

    /// Process a single markdown line.
    fn process_markdown_line(&self, line: &str) -> String {
        let mut result = line.to_string();

        // Remove headers markers but keep text
        if result.starts_with('#') {
            result = result.trim_start_matches('#').trim().to_string();
        }

        // Remove bold/italic markers
        result = result.replace("**", "");
        result = result.replace("__", "");
        result = result.replace('*', "");
        result = result.replace('_', " ");

        // Handle links [text](url) -> text
        result = self.extract_link_text(&result);

        // Remove image syntax ![alt](url)
        result = self.remove_images(&result);

        // Remove inline code backticks but keep content
        result = result.replace('`', "");

        // Clean up multiple spaces
        result = result.split_whitespace().collect::<Vec<_>>().join(" ");

        result
    }

    /// Extract text from markdown links.
    fn extract_link_text(&self, text: &str) -> String {
        let mut result = String::new();
        let mut chars = text.chars().peekable();
        let mut in_link_text = false;
        let mut in_link_url = false;
        let mut link_text = String::new();

        while let Some(c) = chars.next() {
            match c {
                '[' if !in_link_text && !in_link_url => {
                    in_link_text = true;
                }
                ']' if in_link_text => {
                    in_link_text = false;
                    // Check for URL following
                    if chars.peek() == Some(&'(') {
                        chars.next(); // consume '('
                        in_link_url = true;
                        if self.config.include_link_text && !link_text.is_empty() {
                            result.push_str(&link_text);
                            result.push(' ');
                        }
                        link_text.clear();
                    } else {
                        result.push('[');
                        result.push_str(&link_text);
                        result.push(']');
                        link_text.clear();
                    }
                }
                ')' if in_link_url => {
                    in_link_url = false;
                }
                _ if in_link_text => {
                    link_text.push(c);
                }
                _ if in_link_url => {
                    // Skip URL content
                }
                _ => {
                    result.push(c);
                }
            }
        }

        result
    }

    /// Remove image syntax from text.
    fn remove_images(&self, text: &str) -> String {
        let mut result = String::new();
        let mut chars = text.chars().peekable();
        let mut in_image = false;
        let mut paren_depth = 0;

        while let Some(c) = chars.next() {
            if c == '!' && chars.peek() == Some(&'[') {
                in_image = true;
                continue;
            }

            if in_image {
                match c {
                    '(' => paren_depth += 1,
                    ')' => {
                        paren_depth -= 1;
                        if paren_depth == 0 {
                            in_image = false;
                        }
                    }
                    _ => {}
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Extract text from HTML content.
    fn extract_from_html(&self, content: &str) -> ExtractionResult<String> {
        // Simple tag stripping - for production, use a proper HTML parser
        let mut result = String::new();
        let mut in_tag = false;
        let mut in_script = false;
        let mut in_style = false;
        let mut i = 0;
        let chars: Vec<char> = content.chars().collect();

        while i < chars.len() {
            let c = chars[i];

            // Check for script/style start
            if i + 7 < chars.len() {
                let slice: String = chars[i..i + 7].iter().collect();
                if slice.to_lowercase() == "<script" {
                    in_script = true;
                }
                if slice.to_lowercase() == "<style>" || slice.to_lowercase().starts_with("<style ")
                {
                    in_style = true;
                }
            }

            // Check for script/style end
            if i + 9 < chars.len() {
                let slice: String = chars[i..i + 9].iter().collect();
                if slice.to_lowercase() == "</script>" {
                    in_script = false;
                    i += 9;
                    continue;
                }
            }
            if i + 8 < chars.len() {
                let slice: String = chars[i..i + 8].iter().collect();
                if slice.to_lowercase() == "</style>" {
                    in_style = false;
                    i += 8;
                    continue;
                }
            }

            if in_script || in_style {
                i += 1;
                continue;
            }

            match c {
                '<' => in_tag = true,
                '>' => {
                    in_tag = false;
                    result.push(' '); // Replace tags with space
                }
                _ if !in_tag => {
                    result.push(c);
                }
                _ => {}
            }

            i += 1;
        }

        // Decode common HTML entities
        let result = result
            .replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'");

        // Clean up whitespace
        let result = result
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(result)
    }
}

impl Default for DocumentExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracted document information.
#[derive(Debug, Clone)]
pub struct ExtractedDocument {
    /// Extracted plain text content.
    pub text: String,
    /// Detected or provided format.
    pub format: DocumentFormat,
    /// Original content length.
    pub original_length: usize,
    /// Extracted text length.
    pub extracted_length: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_from_extension() {
        assert_eq!(
            DocumentFormat::from_extension("md"),
            Some(DocumentFormat::Markdown)
        );
        assert_eq!(
            DocumentFormat::from_extension("txt"),
            Some(DocumentFormat::PlainText)
        );
        assert_eq!(
            DocumentFormat::from_extension("html"),
            Some(DocumentFormat::Html)
        );
        assert_eq!(
            DocumentFormat::from_extension("pdf"),
            Some(DocumentFormat::Pdf)
        );
        assert_eq!(DocumentFormat::from_extension("docx"), None);
    }

    #[test]
    fn test_format_detection_from_mime() {
        assert_eq!(
            DocumentFormat::from_mime_type("text/markdown"),
            Some(DocumentFormat::Markdown)
        );
        assert_eq!(
            DocumentFormat::from_mime_type("text/plain"),
            Some(DocumentFormat::PlainText)
        );
        assert_eq!(
            DocumentFormat::from_mime_type("application/pdf"),
            Some(DocumentFormat::Pdf)
        );
    }

    #[test]
    fn test_extract_plain_text() {
        let extractor = DocumentExtractor::new();
        let text = "This is plain text content.";
        let result = extractor
            .extract_text(text, DocumentFormat::PlainText)
            .unwrap();
        assert_eq!(result, text);
    }

    #[test]
    fn test_extract_markdown_headers() {
        let extractor = DocumentExtractor::new();
        let markdown = "# Heading 1\n## Heading 2\nParagraph text.";
        let result = extractor
            .extract_text(markdown, DocumentFormat::Markdown)
            .unwrap();

        assert!(result.contains("Heading 1"));
        assert!(result.contains("Heading 2"));
        assert!(result.contains("Paragraph text"));
        assert!(!result.contains('#'));
    }

    #[test]
    fn test_extract_markdown_bold_italic() {
        let extractor = DocumentExtractor::new();
        let markdown = "**bold** and *italic* and __also bold__";
        let result = extractor
            .extract_text(markdown, DocumentFormat::Markdown)
            .unwrap();

        assert!(result.contains("bold"));
        assert!(result.contains("italic"));
        assert!(!result.contains("**"));
        assert!(!result.contains("__"));
    }

    #[test]
    fn test_extract_markdown_links() {
        let extractor = DocumentExtractor::new();
        let markdown = "Click [here](https://example.com) for more info.";
        let result = extractor
            .extract_text(markdown, DocumentFormat::Markdown)
            .unwrap();

        assert!(result.contains("here"));
        assert!(!result.contains("https://example.com"));
    }

    #[test]
    fn test_extract_markdown_code_blocks() {
        let config = ExtractionConfig {
            preserve_code_blocks: true,
            ..Default::default()
        };
        let extractor = DocumentExtractor::with_config(config);

        let markdown = "Before\n```python\ndef hello():\n    pass\n```\nAfter";
        let result = extractor
            .extract_text(markdown, DocumentFormat::Markdown)
            .unwrap();

        assert!(result.contains("Before"));
        assert!(result.contains("After"));
        assert!(result.contains("def hello()"));
    }

    #[test]
    fn test_extract_html_basic() {
        let extractor = DocumentExtractor::new();
        let html = "<html><body><h1>Title</h1><p>Paragraph text.</p></body></html>";
        let result = extractor.extract_text(html, DocumentFormat::Html).unwrap();

        assert!(result.contains("Title"));
        assert!(result.contains("Paragraph text"));
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
    }

    #[test]
    fn test_extract_html_with_script() {
        let extractor = DocumentExtractor::new();
        let html = "<p>Text</p><script>alert('hi');</script><p>More text</p>";
        let result = extractor.extract_text(html, DocumentFormat::Html).unwrap();

        assert!(result.contains("Text"));
        assert!(result.contains("More text"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_extract_html_entities() {
        let extractor = DocumentExtractor::new();
        let html = "<p>Tom &amp; Jerry &lt;3</p>";
        let result = extractor.extract_text(html, DocumentFormat::Html).unwrap();

        assert!(result.contains("Tom & Jerry <3"));
    }

    #[test]
    fn test_empty_document_error() {
        let extractor = DocumentExtractor::new();
        let result = extractor.extract_text("", DocumentFormat::PlainText);
        assert!(matches!(result, Err(ExtractionError::EmptyDocument)));
    }

    #[test]
    fn test_too_large_error() {
        let config = ExtractionConfig {
            max_size: 100,
            ..Default::default()
        };
        let extractor = DocumentExtractor::with_config(config);
        let large_content = "x".repeat(200);

        let result = extractor.extract_text(&large_content, DocumentFormat::PlainText);
        assert!(matches!(result, Err(ExtractionError::TooLarge(100))));
    }

    #[test]
    fn test_pdf_feature_required() {
        let extractor = DocumentExtractor::new();
        let result = extractor.extract_text("binary pdf content", DocumentFormat::Pdf);
        assert!(matches!(result, Err(ExtractionError::PdfFeatureRequired)));
    }

    #[test]
    fn test_auto_detection() {
        let extractor = DocumentExtractor::new();

        // By filename
        let result = extractor
            .extract_text_auto("# Heading with more content here", Some("doc.md"), None)
            .unwrap();
        assert!(result.contains("Heading"));

        // By mime type
        let result = extractor
            .extract_text_auto(
                "<p>Text with more content here</p>",
                None,
                Some("text/html"),
            )
            .unwrap();
        assert!(result.contains("Text"));

        // Default to plain text
        let result = extractor
            .extract_text_auto("Plain content with more text", None, None)
            .unwrap();
        assert!(result.contains("Plain content"));
    }
}
