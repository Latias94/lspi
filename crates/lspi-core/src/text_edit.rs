use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    /// UTF-16 code unit offset within the line.
    pub character: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEdit {
    pub range: Range,
    pub new_text: String,
}

pub fn apply_text_edits_utf16(content: &str, edits: &[TextEdit]) -> Result<String> {
    if edits.is_empty() {
        return Ok(content.to_string());
    }

    let line_starts = compute_line_starts(content);
    let mut replacements = Vec::with_capacity(edits.len());

    for (idx, edit) in edits.iter().enumerate() {
        let start = position_to_offset(&line_starts, content, &edit.range.start)
            .with_context(|| format!("invalid start position for edit #{idx}"))?;
        let end = position_to_offset(&line_starts, content, &edit.range.end)
            .with_context(|| format!("invalid end position for edit #{idx}"))?;

        if start > end {
            return Err(anyhow!(
                "invalid range for edit #{idx}: start offset {start} > end offset {end}"
            ));
        }

        replacements.push((start, end, edit.new_text.as_str()));
    }

    replacements.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    let mut out = content.to_string();
    for (start, end, new_text) in replacements {
        out.replace_range(start..end, new_text);
    }

    Ok(out)
}

fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (i, b) in content.as_bytes().iter().enumerate() {
        if *b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn position_to_offset(line_starts: &[usize], content: &str, pos: &Position) -> Result<usize> {
    let line = pos.line as usize;
    if line >= line_starts.len() {
        return Err(anyhow!(
            "line {} is out of range (file has {} lines)",
            pos.line,
            line_starts.len()
        ));
    }

    let line_start = line_starts[line];
    let line_end_including_eol = if line + 1 < line_starts.len() {
        line_starts[line + 1]
    } else {
        content.len()
    };

    let mut line_end = line_end_including_eol;
    if line_end > line_start && content.as_bytes()[line_end - 1] == b'\n' {
        line_end -= 1;
    }
    if line_end > line_start && content.as_bytes()[line_end - 1] == b'\r' {
        line_end -= 1;
    }

    let line_text = &content[line_start..line_end];
    let byte_in_line = utf16_col_to_byte_idx(line_text, pos.character);
    Ok((line_start + byte_in_line).min(content.len()))
}

fn utf16_col_to_byte_idx(line: &str, utf16_col: u32) -> usize {
    if utf16_col == 0 {
        return 0;
    }

    let mut units = 0u32;

    for (byte_idx, ch) in line.char_indices() {
        if units == utf16_col {
            return byte_idx;
        }

        units = units.saturating_add(ch.len_utf16() as u32);
        let end = byte_idx + ch.len_utf8();

        if units > utf16_col {
            // Avoid slicing in the middle of a Unicode scalar value.
            return end;
        }
    }

    if units == utf16_col {
        return line.len();
    }

    line.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_utf16_edit_over_surrogate_pair() {
        // 😀 is a surrogate pair in UTF-16 (2 code units).
        let content = "a😀b\n";
        let edits = vec![TextEdit {
            range: Range {
                start: Position {
                    line: 0,
                    character: 1,
                },
                end: Position {
                    line: 0,
                    character: 3,
                },
            },
            new_text: "X".to_string(),
        }];
        let out = apply_text_edits_utf16(content, &edits).unwrap();
        assert_eq!(out, "aXb\n");
    }
}
