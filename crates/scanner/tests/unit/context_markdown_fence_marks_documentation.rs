//! Markdown code fences mark enclosed lines as documentation.

use keyhog_scanner::context::{documentation_line_flags, infer_context, CodeContext};

#[test]
fn context_markdown_fence_marks_documentation() {
    let lines = vec!["```python", r#"api_key = "sk-proj-demo""#, "```"];
    assert!(documentation_line_flags(&lines)[1], "fence interior is documentation");
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::Documentation,
        "infer_context must classify fenced example as documentation"
    );
}
