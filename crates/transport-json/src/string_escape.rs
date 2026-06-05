/// JSON string escape rejection helpers shared by chain-event-ref and
/// ciphertext envelope decoders.
use super::json_codec::JsonParseError;

pub(super) fn reject_json_string_escape_in_top_level_object(
    text: &str,
) -> Result<(), JsonParseError> {
    let Some(start) = first_non_whitespace(text) else {
        return Ok(());
    };
    if text.as_bytes()[start] != b'{' {
        return Ok(());
    }

    reject_json_string_escape_until_top_level_close(text, start)
}

pub(super) fn reject_json_string_escape_in_top_level_string(
    text: &str,
) -> Result<(), JsonParseError> {
    let Some(start) = first_non_whitespace(text) else {
        return Ok(());
    };
    if text.as_bytes()[start] != b'"' {
        return Ok(());
    }

    let mut escaped = false;
    for byte in text.bytes().skip(start + 1) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => return Err(JsonParseError::UnsupportedStringEscape),
            b'"' => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn first_non_whitespace(text: &str) -> Option<usize> {
    text.bytes()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
}

fn reject_json_string_escape_until_top_level_close(
    text: &str,
    start: usize,
) -> Result<(), JsonParseError> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut reject_current_string = false;
    let mut escaped = false;
    let mut index = start;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else {
                match byte {
                    b'\\' if reject_current_string => {
                        return Err(JsonParseError::UnsupportedStringEscape);
                    }
                    b'\\' => escaped = true,
                    b'"' => {
                        in_string = false;
                        reject_current_string = false;
                    }
                    _ => {}
                }
            }
            index += 1;
            continue;
        }

        match byte {
            b'"' => {
                in_string = true;
                reject_current_string = depth == 1;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(());
                }
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}
