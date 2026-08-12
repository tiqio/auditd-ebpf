#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct RuleErrors(pub Vec<Diagnostic>);

impl RuleErrors {
    pub fn one(file: &str, line: usize, code: &'static str, message: impl Into<String>) -> Self {
        Self(vec![Diagnostic {
            code,
            file: file.into(),
            line,
            column: 1,
            message: message.into(),
        }])
    }
}

impl core::fmt::Display for RuleErrors {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, diagnostic) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            write!(
                formatter,
                "{}:{}:{} {} {}",
                diagnostic.file,
                diagnostic.line,
                diagnostic.column,
                diagnostic.code,
                diagnostic.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for RuleErrors {}
