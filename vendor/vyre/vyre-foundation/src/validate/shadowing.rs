use crate::validate::{err, Binding, ValidationError, ValidationOptions};
use rustc_hash::FxHashMap;

#[inline]
pub(crate) fn check_local(
    name: &str,
    scope: &FxHashMap<String, Binding>,
    options: ValidationOptions<'_>,
    errors: &mut Vec<ValidationError>,
) {
    if !options.allow_shadowing && scope.contains_key(name) {
        errors.push(err(format!(
            "V008: duplicate local binding `{name}` shadows an outer scope. Fix: choose a unique local name, or opt into nested shadowing with ValidationOptions::with_shadowing(true)."
        )));
    }
}
