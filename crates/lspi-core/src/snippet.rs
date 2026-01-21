use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snippet {
    /// 0-based line number of the first line in `text`.
    pub start_line: u32,
    pub text: String,
    pub truncated: bool,
}

pub fn extract_snippet(
    content: &str,
    center_line: u32,
    context_lines: usize,
    max_chars: usize,
) -> Result<Snippet> {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    if lines.is_empty() {
        return Ok(Snippet {
            start_line: 0,
            text: String::new(),
            truncated: false,
        });
    }

    let total_lines = lines.len();
    let center = (center_line as usize).min(total_lines.saturating_sub(1));
    let start = center.saturating_sub(context_lines);
    let end = (center + context_lines + 1).min(total_lines);

    let mut out = String::new();
    for l in &lines[start..end] {
        out.push_str(l);
    }

    let mut truncated = false;
    if out.chars().count() > max_chars {
        truncated = true;
        out = out.chars().take(max_chars).collect::<String>();
    }

    Ok(Snippet {
        start_line: start as u32,
        text: out,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_context_lines() {
        let content = "a\nb\nc\nd\ne\n";
        let s = extract_snippet(content, 2, 1, 100).unwrap();
        assert_eq!(s.start_line, 1);
        assert_eq!(s.text, "b\nc\nd\n");
        assert!(!s.truncated);
    }

    #[test]
    fn truncates_by_char_count() {
        let content = "0123456789\n";
        let s = extract_snippet(content, 0, 0, 5).unwrap();
        assert_eq!(s.text, "01234");
        assert!(s.truncated);
    }
}
