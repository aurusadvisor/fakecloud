/// Offset-based pagination helper for AWS list operations.
///
/// Parses `next_token` as a numeric offset (defaulting to 0 if `None` or unparseable),
/// slices `items` starting at that offset, and returns at most `max_results` items
/// along with an optional next token for the following page.
pub fn paginate<T: Clone>(
    items: &[T],
    next_token: Option<&str>,
    max_results: usize,
) -> (Vec<T>, Option<String>) {
    if max_results == 0 {
        return (Vec::new(), None);
    }
    let offset: usize = next_token.and_then(|s| s.parse().ok()).unwrap_or(0);
    let page = if offset < items.len() {
        &items[offset..]
    } else {
        &[][..]
    };
    let has_more = page.len() > max_results;
    let result: Vec<T> = page.iter().take(max_results).cloned().collect();
    let token = if has_more {
        Some((offset + max_results).to_string())
    } else {
        None
    };
    (result, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_page() {
        let items: Vec<i32> = (0..10).collect();
        let (page, token) = paginate(&items, None, 3);
        assert_eq!(page, vec![0, 1, 2]);
        assert_eq!(token, Some("3".to_string()));
    }

    #[test]
    fn middle_page() {
        let items: Vec<i32> = (0..10).collect();
        let (page, token) = paginate(&items, Some("3"), 3);
        assert_eq!(page, vec![3, 4, 5]);
        assert_eq!(token, Some("6".to_string()));
    }

    #[test]
    fn last_page() {
        let items: Vec<i32> = (0..10).collect();
        let (page, token) = paginate(&items, Some("9"), 3);
        assert_eq!(page, vec![9]);
        assert_eq!(token, None);
    }

    #[test]
    fn exact_page_boundary() {
        let items: Vec<i32> = (0..6).collect();
        let (page, token) = paginate(&items, Some("3"), 3);
        assert_eq!(page, vec![3, 4, 5]);
        assert_eq!(token, None);
    }

    #[test]
    fn offset_beyond_items() {
        let items: Vec<i32> = (0..3).collect();
        let (page, token) = paginate(&items, Some("100"), 3);
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[test]
    fn invalid_token_defaults_to_zero() {
        let items: Vec<i32> = (0..5).collect();
        let (page, token) = paginate(&items, Some("not_a_number"), 3);
        assert_eq!(page, vec![0, 1, 2]);
        assert_eq!(token, Some("3".to_string()));
    }

    #[test]
    fn zero_max_results_returns_empty_page_without_token() {
        // AWS list ops reject MaxResults=0 at the validation layer; if the helper
        // ever sees zero it returns an empty page with no continuation token so
        // callers can't accidentally paginate forever on a non-advancing offset.
        let items: Vec<i32> = (0..5).collect();
        let (page, token) = paginate(&items, None, 0);
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[test]
    fn empty_items() {
        let items: Vec<i32> = vec![];
        let (page, token) = paginate(&items, None, 10);
        assert!(page.is_empty());
        assert_eq!(token, None);
    }
}
