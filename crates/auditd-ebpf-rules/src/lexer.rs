use crate::diagnostic::RuleErrors;

pub fn tokenize<'a>(
    file: &str,
    line_number: usize,
    line: &'a str,
) -> Result<Vec<&'a str>, RuleErrors> {
    if line
        .bytes()
        .any(|byte| byte == 0 || (byte < 0x20 && byte != b'\t'))
    {
        return Err(RuleErrors::one(
            file,
            line_number,
            "E_CONTROL",
            "规则包含控制字符",
        ));
    }
    Ok(line.split_ascii_whitespace().collect())
}
