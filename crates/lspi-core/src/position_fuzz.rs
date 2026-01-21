use std::collections::HashSet;

use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub struct CandidateLimits {
    pub line_window: i32,
    pub character_window: i32,
    pub max_candidates: usize,
}

impl Default for CandidateLimits {
    fn default() -> Self {
        Self {
            line_window: 1,
            character_window: 2,
            max_candidates: 50,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LspPosition {
    pub line: u32,
    /// UTF-16 code unit offset within the line.
    pub character: u32,
}

/// Generate a bounded set of candidate positions in LSP coordinates (0-based, UTF-16).
///
/// This is designed to be robust to common AI position errors:
/// - 0-based vs 1-based confusion
/// - Unicode scalar index vs UTF-16 code unit offset vs byte offset
/// - off-by-one around whitespace/punctuation
pub fn candidate_lsp_positions(
    content: &str,
    input_line: u32,
    input_character: u32,
    limits: CandidateLimits,
) -> Result<Vec<LspPosition>> {
    let line_spans = compute_line_spans(content);
    if line_spans.is_empty() {
        return Ok(vec![LspPosition {
            line: 0,
            character: 0,
        }]);
    }

    let mut results = Vec::new();
    let mut seen = HashSet::<(u32, u32)>::new();

    // 1) Best-guess: treat input as 1-based and convert to 0-based.
    let best_line0 = input_line.saturating_sub(1);
    let best_char0 = input_character.saturating_sub(1);
    push_candidate(
        &mut results,
        &mut seen,
        clamp_line(best_line0, line_spans.len()),
        clamp_character(content, &line_spans, best_line0, best_char0),
        limits.max_candidates,
    );

    // 2) Alternative base: treat input as already 0-based.
    push_candidate(
        &mut results,
        &mut seen,
        clamp_line(input_line, line_spans.len()),
        clamp_character(content, &line_spans, input_line, input_character),
        limits.max_candidates,
    );

    // 3) Expand around plausible line interpretations.
    let mut base_lines = Vec::new();
    base_lines.push(best_line0);
    base_lines.push(input_line);
    base_lines.sort_unstable();
    base_lines.dedup();

    for base in base_lines {
        for dl in -limits.line_window..=limits.line_window {
            let line = clamp_line(base.saturating_add_signed(dl), line_spans.len());
            let line_text = &content[line_spans[line as usize].0..line_spans[line as usize].1];
            let line_utf16_len = utf16_len(line_text);

            // 4) Character base candidates: raw, scalar-index interpreted, byte-index interpreted.
            let mut base_chars = Vec::<u32>::new();
            base_chars.push(input_character.saturating_sub(1));
            base_chars.push(input_character);

            base_chars.push(utf16_units_for_scalar_index(
                line_text,
                input_character.saturating_sub(1),
            ));
            base_chars.push(utf16_units_for_scalar_index(line_text, input_character));

            base_chars.push(utf16_units_for_byte_offset(
                line_text,
                (input_character.saturating_sub(1)) as usize,
            ));
            base_chars.push(utf16_units_for_byte_offset(
                line_text,
                input_character as usize,
            ));

            base_chars.sort_unstable();
            base_chars.dedup();

            for base_char in base_chars {
                for dc in -limits.character_window..=limits.character_window {
                    let ch = clamp_u32(base_char.saturating_add_signed(dc), 0, line_utf16_len);
                    push_candidate(&mut results, &mut seen, line, ch, limits.max_candidates);
                    if results.len() >= limits.max_candidates {
                        return Ok(results);
                    }
                }
            }
        }
    }

    Ok(results)
}

fn push_candidate(
    out: &mut Vec<LspPosition>,
    seen: &mut HashSet<(u32, u32)>,
    line: u32,
    character: u32,
    max: usize,
) {
    if out.len() >= max {
        return;
    }
    if seen.insert((line, character)) {
        out.push(LspPosition { line, character });
    }
}

fn compute_line_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut start = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            let mut end = i;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            spans.push((start, end));
            start = i + 1;
        }
    }
    if start <= content.len() {
        let mut end = content.len();
        if end > start && bytes[end - 1] == b'\n' {
            end -= 1;
        }
        if end > start && bytes[end - 1] == b'\r' {
            end -= 1;
        }
        spans.push((start, end));
    }
    spans
}

fn clamp_line(line: u32, total_lines: usize) -> u32 {
    if total_lines == 0 {
        return 0;
    }
    line.min((total_lines - 1) as u32)
}

fn clamp_u32(value: u32, min: u32, max: u32) -> u32 {
    value.max(min).min(max)
}

fn clamp_character(content: &str, spans: &[(usize, usize)], line: u32, character: u32) -> u32 {
    let Some((start, end)) = spans.get(line as usize).copied() else {
        return 0;
    };
    let line_text = &content[start..end];
    let max = utf16_len(line_text);
    clamp_u32(character, 0, max)
}

fn utf16_len(text: &str) -> u32 {
    text.chars().map(|c| c.len_utf16() as u32).sum()
}

fn utf16_units_for_scalar_index(text: &str, scalar_index: u32) -> u32 {
    let mut scalars = 0u32;
    let mut units = 0u32;
    for ch in text.chars() {
        if scalars >= scalar_index {
            break;
        }
        units = units.saturating_add(ch.len_utf16() as u32);
        scalars += 1;
    }
    units
}

fn utf16_units_for_byte_offset(text: &str, byte_offset: usize) -> u32 {
    let byte_offset = byte_offset.min(text.len());
    if byte_offset == text.len() {
        return utf16_len(text);
    }

    let mut boundary = 0usize;
    for (idx, _) in text.char_indices() {
        if idx <= byte_offset {
            boundary = idx;
        } else {
            break;
        }
    }

    utf16_len(&text[..boundary])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_candidate_is_1_based_mapping_when_possible() {
        let content = "fn main() {\n    let x = 1;\n}\n";
        let candidates =
            candidate_lsp_positions(content, 2, 5, CandidateLimits::default()).unwrap();
        assert!(!candidates.is_empty());
        assert_eq!(
            candidates[0],
            LspPosition {
                line: 1,
                character: 4
            }
        );
    }

    #[test]
    fn scalar_vs_utf16_candidate_differs_for_surrogate() {
        let content = "a😀b\n";
        // line=1, "😀" is scalar index 2 (1-based); UTF-16 column at that point is 1.
        let candidates =
            candidate_lsp_positions(content, 1, 2, CandidateLimits::default()).unwrap();
        assert!(candidates.iter().any(|p| p.line == 0 && p.character == 1));
        // Also keep raw mapping: character-1 = 1.
        assert_eq!(
            candidates[0],
            LspPosition {
                line: 0,
                character: 1
            }
        );
    }
}
