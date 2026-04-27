use std::fs;
use std::path::Path;

pub(crate) fn scoped_category_check(
    op: &crate::quick::quick_op::QuickOp,
    source_file: &Path,
) -> (crate::quick::quick_status::QuickStatus, String) {
    let source = match fs::read_to_string(source_file) {
        Ok(source) => source,
        Err(err) => {
            return (
                crate::quick::quick_status::QuickStatus::Fail,
                format!("could not read {}: {err}", source_file.display()),
            );
        }
    };

    if !source.contains(op.id) {
        return (
            crate::quick::quick_status::QuickStatus::Fail,
            format!("{} does not declare {}", source_file.display(), op.id),
        );
    }
    if source.contains("Box<dyn Op>") || source.contains("&dyn Op") {
        return (
            crate::quick::quick_status::QuickStatus::Fail,
            format!(
                "Category B dynamic op dispatch in {}",
                source_file.display()
            ),
        );
    }
    if source.contains("Opcode::") && !source_file.display().to_string().contains("bytecode") {
        return (
            crate::quick::quick_status::QuickStatus::Fail,
            format!("Category B interpreter loop in {}", source_file.display()),
        );
    }

    if source.contains("category_a_self") || source.contains("Category::Intrinsic") {
        (
            crate::quick::quick_status::QuickStatus::Pass,
            format!("category checks scoped to {}", source_file.display()),
        )
    } else {
        (
            crate::quick::quick_status::QuickStatus::Fail,
            "missing Category A/C declaration in op source".to_string(),
        )
    }
}
