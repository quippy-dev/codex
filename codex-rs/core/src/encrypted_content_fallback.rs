use crate::api_error_envelope::is_invalid_encrypted_content_error;
use crate::error::CodexErr;
use codex_protocol::models::ResponseItem;

/// Returns true when a request should perform a single retry with encrypted
/// content removed from request input.
pub(crate) fn should_retry_with_sanitized_encrypted_content(
    already_retried_with_sanitized_input: bool,
    err: &CodexErr,
) -> bool {
    !already_retried_with_sanitized_input && is_invalid_encrypted_content_error(err)
}

/// Applies the invalid encrypted-content fallback in-place and returns true
/// when caller should retry the request immediately.
pub(crate) fn apply_invalid_encrypted_content_fallback(
    already_retried_with_sanitized_input: &mut bool,
    err: &CodexErr,
    input: &mut Vec<ResponseItem>,
) -> bool {
    if !should_retry_with_sanitized_encrypted_content(*already_retried_with_sanitized_input, err) {
        return false;
    }

    *already_retried_with_sanitized_input = true;
    sanitize_request_input_for_encrypted_content_fallback(input);
    true
}

/// Sanitizes request input for the encrypted-content fallback path.
///
/// - Removes all compaction items.
/// - Clears `Reasoning.encrypted_content` values.
pub(crate) fn sanitize_request_input_for_encrypted_content_fallback(input: &mut Vec<ResponseItem>) {
    input.retain(|item| !matches!(item, ResponseItem::Compaction { .. }));

    for item in input {
        if let ResponseItem::Reasoning {
            encrypted_content, ..
        } = item
        {
            *encrypted_content = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::ReasoningItemContent;
    use codex_protocol::models::ReasoningItemReasoningSummary;
    use pretty_assertions::assert_eq;

    fn invalid_encrypted_content_err() -> CodexErr {
        CodexErr::InvalidRequest(
            r#"{"error":{"message":"bad request","type":"invalid_request_error","code":"invalid_encrypted_content"}}"#
                .to_string(),
        )
    }

    #[test]
    fn retry_policy_matches_invalid_request_rejection() {
        let err = invalid_encrypted_content_err();

        let should_retry = should_retry_with_sanitized_encrypted_content(false, &err);

        assert_eq!(should_retry, true);
    }

    #[test]
    fn retry_policy_is_one_shot() {
        let err = invalid_encrypted_content_err();

        let should_retry = should_retry_with_sanitized_encrypted_content(true, &err);

        assert_eq!(should_retry, false);
    }

    #[test]
    fn retry_policy_matches_bad_request_unexpected_status_rejection() {
        let err = CodexErr::UnexpectedStatus(crate::error::UnexpectedResponseError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: r#"{"error":{"message":"bad request","type":"invalid_request_error","code":"invalid_encrypted_content"}}"#
                .to_string(),
            url: None,
            cf_ray: None,
            request_id: None,
        });

        let should_retry = should_retry_with_sanitized_encrypted_content(false, &err);

        assert_eq!(should_retry, true);
    }

    #[test]
    fn retry_policy_ignores_unrelated_errors() {
        let err = CodexErr::InvalidRequest("unrelated validation failure".to_string());

        let should_retry = should_retry_with_sanitized_encrypted_content(false, &err);

        assert_eq!(should_retry, false);
    }

    #[test]
    fn sanitizer_strips_reasoning_encrypted_content_and_compaction_items() {
        let mut input = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "hello".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Reasoning {
                id: "reasoning-1".to_string(),
                summary: vec![ReasoningItemReasoningSummary::SummaryText {
                    text: "summary".to_string(),
                }],
                content: Some(vec![ReasoningItemContent::ReasoningText {
                    text: "details".to_string(),
                }]),
                encrypted_content: Some("opaque".to_string()),
            },
            ResponseItem::Compaction {
                encrypted_content: "encrypted-compaction".to_string(),
            },
        ];

        sanitize_request_input_for_encrypted_content_fallback(&mut input);

        let expected = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "hello".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Reasoning {
                id: "reasoning-1".to_string(),
                summary: vec![ReasoningItemReasoningSummary::SummaryText {
                    text: "summary".to_string(),
                }],
                content: Some(vec![ReasoningItemContent::ReasoningText {
                    text: "details".to_string(),
                }]),
                encrypted_content: None,
            },
        ];
        assert_eq!(input, expected);
    }

    #[test]
    fn apply_fallback_sets_retry_flag_and_sanitizes_input() {
        let err = invalid_encrypted_content_err();
        let mut already_retried_with_sanitized_input = false;
        let mut input = vec![
            ResponseItem::Reasoning {
                id: "reasoning-1".to_string(),
                summary: vec![],
                content: None,
                encrypted_content: Some("opaque".to_string()),
            },
            ResponseItem::Compaction {
                encrypted_content: "encrypted-compaction".to_string(),
            },
        ];

        let should_retry = apply_invalid_encrypted_content_fallback(
            &mut already_retried_with_sanitized_input,
            &err,
            &mut input,
        );

        assert_eq!(should_retry, true);
        assert_eq!(already_retried_with_sanitized_input, true);
        assert_eq!(
            input,
            vec![ResponseItem::Reasoning {
                id: "reasoning-1".to_string(),
                summary: vec![],
                content: None,
                encrypted_content: None,
            }]
        );
    }
}
