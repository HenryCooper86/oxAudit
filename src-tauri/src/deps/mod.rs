pub mod lockfiles;
pub mod osv;

const MAX_FAILED_LOCKFILES_IN_MESSAGE: usize = 5;
const MAX_PARSE_ERROR_CHARS: usize = 280;

/// Refuse to present dependency results when any discovered lockfile could not
/// be parsed. A partial inventory cannot support a clean vulnerability result.
///
/// Parser errors originate in files under the scanned project, so bound both
/// the number and length included in the user-facing error.
pub fn ensure_complete_lockfile_coverage(parse_errors: &[String]) -> Result<(), String> {
    if parse_errors.is_empty() {
        return Ok(());
    }

    let failed = parse_errors
        .iter()
        .take(MAX_FAILED_LOCKFILES_IN_MESSAGE)
        .map(|error| {
            let mut bounded = error
                .chars()
                .take(MAX_PARSE_ERROR_CHARS)
                .collect::<String>();
            if error.chars().count() > MAX_PARSE_ERROR_CHARS {
                bounded.push('…');
            }
            bounded
        })
        .collect::<Vec<_>>();
    let remaining = parse_errors.len().saturating_sub(failed.len());
    let suffix = if remaining == 0 {
        String::new()
    } else {
        format!("; and {remaining} more")
    };

    Err(format!(
        "incomplete dependency coverage: {} lockfile(s) failed to parse: {}{}. Fix or exclude the failed lockfiles before checking advisories.",
        parse_errors.len(),
        failed.join("; "),
        suffix,
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_complete_lockfile_coverage;

    #[test]
    fn complete_coverage_accepts_an_empty_parser_error_list() {
        // A parser that successfully produces an empty inventory must remain
        // distinguishable from a parser failure.
        assert!(ensure_complete_lockfile_coverage(&[]).is_ok());
    }

    #[test]
    fn incomplete_coverage_names_failed_lockfiles_in_a_bounded_error() {
        let errors = (0..7)
            .map(|index| format!("project-{index}/package-lock.json: invalid JSON"))
            .collect::<Vec<_>>();

        let error = ensure_complete_lockfile_coverage(&errors).expect_err("coverage is incomplete");

        assert!(
            error.starts_with("incomplete dependency coverage:"),
            "{error}"
        );
        assert!(error.contains("project-0/package-lock.json"), "{error}");
        assert!(error.contains("and 2 more"), "{error}");
        assert!(!error.contains("project-6/package-lock.json"), "{error}");
    }
}
