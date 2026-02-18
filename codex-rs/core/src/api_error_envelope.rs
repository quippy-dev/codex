use crate::error::CodexErr;
use crate::error::UnexpectedResponseError;
use serde::Deserialize;

const INVALID_ENCRYPTED_CONTENT: &str = "invalid_encrypted_content";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiErrorEnvelope {
    pub(crate) message: Option<String>,
    pub(crate) error_type: Option<String>,
    pub(crate) code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelopeBody {
    error: Option<ErrorEnvelopeValue>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelopeValue {
    message: Option<String>,
    #[serde(rename = "type")]
    error_type: Option<String>,
    code: Option<String>,
}

pub(crate) fn parse_api_error_envelope(body: &str) -> Option<ApiErrorEnvelope> {
    let parsed = serde_json::from_str::<ErrorEnvelopeBody>(body).ok()?;
    let error = parsed.error?;
    Some(ApiErrorEnvelope {
        message: trim_to_non_empty(error.message),
        error_type: trim_to_non_empty(error.error_type),
        code: trim_to_non_empty(error.code),
    })
}

pub(crate) fn is_invalid_encrypted_content_error(err: &CodexErr) -> bool {
    match err {
        CodexErr::InvalidRequest(body) => body_is_invalid_encrypted_content(body),
        CodexErr::UnexpectedStatus(UnexpectedResponseError { body, .. }) => {
            body_is_invalid_encrypted_content(body)
        }
        _ => false,
    }
}

fn body_is_invalid_encrypted_content(body: &str) -> bool {
    parse_api_error_envelope(body).is_some_and(|envelope| {
        [
            envelope.code.as_deref(),
            envelope.error_type.as_deref(),
            envelope.message.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(is_invalid_encrypted_content_value)
    })
}

fn is_invalid_encrypted_content_value(value: &str) -> bool {
    let normalized = value.trim();
    normalized.eq_ignore_ascii_case(INVALID_ENCRYPTED_CONTENT)
        || normalized
            .to_ascii_lowercase()
            .contains(INVALID_ENCRYPTED_CONTENT)
}

fn trim_to_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use reqwest::StatusCode;

    #[test]
    fn parse_api_error_envelope_reads_message_type_and_code() {
        let body = r#"{
            "error": {
                "message": " encrypted payload failed ",
                "type": " invalid_request_error ",
                "code": " invalid_encrypted_content "
            }
        }"#;

        assert_eq!(
            parse_api_error_envelope(body),
            Some(ApiErrorEnvelope {
                message: Some("encrypted payload failed".to_string()),
                error_type: Some("invalid_request_error".to_string()),
                code: Some("invalid_encrypted_content".to_string()),
            })
        );
    }

    #[test]
    fn parse_api_error_envelope_returns_none_for_invalid_or_missing_error() {
        assert_eq!(parse_api_error_envelope("not-json"), None);
        assert_eq!(parse_api_error_envelope(r#"{"ok":true}"#), None);
    }

    #[test]
    fn invalid_encrypted_content_matches_invalid_request_code() {
        let err = CodexErr::InvalidRequest(
            r#"{"error":{"message":"bad request","type":"invalid_request_error","code":"invalid_encrypted_content"}}"#
                .to_string(),
        );

        assert_eq!(is_invalid_encrypted_content_error(&err), true);
    }

    #[test]
    fn invalid_encrypted_content_matches_unexpected_status_type() {
        let err = CodexErr::UnexpectedStatus(UnexpectedResponseError {
            status: StatusCode::BAD_REQUEST,
            body: r#"{"error":{"message":"oops","type":"invalid_encrypted_content","code":"invalid_request_error"}}"#
                .to_string(),
            url: None,
            cf_ray: None,
            request_id: None,
        });

        assert_eq!(is_invalid_encrypted_content_error(&err), true);
    }

    #[test]
    fn invalid_encrypted_content_returns_false_for_non_matching_payloads() {
        let err = CodexErr::UnexpectedStatus(UnexpectedResponseError {
            status: StatusCode::BAD_REQUEST,
            body: r#"{"error":{"message":"different","type":"invalid_request_error","code":"other_code"}}"#
                .to_string(),
            url: None,
            cf_ray: None,
            request_id: None,
        });

        assert_eq!(is_invalid_encrypted_content_error(&err), false);
        assert_eq!(
            is_invalid_encrypted_content_error(&CodexErr::InvalidRequest("plain text".to_string())),
            false
        );
    }
}
