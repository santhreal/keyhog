use naga::Module;
use std::fs::File;
use std::io::{BufRead, BufReader};
use vyre_emit_naga::BindResultEntry;

pub struct FailureTrace {
    pub text: String,
}

pub fn failure_trace(module: &Module, error: &naga::valid::ValidationError) -> FailureTrace {
    let text = format!(
        "FAILURE: {:#?}\nentry_points={}\nfunctions={}\nglobals={}",
        error,
        module.entry_points.len(),
        module.functions.len(),
        module.global_variables.len()
    );
    FailureTrace { text }
}

pub fn failure_trace_wgsl(
    module: &Module,
    info: &naga::valid::ModuleInfo,
    err: &naga::back::wgsl::Error,
) -> FailureTrace {
    let text = format!(
        "FAILURE: {:#?}\nentry_points={}\nfunctions={}\nglobals={}\nmodule_info={:#?}",
        err,
        module.entry_points.len(),
        module.functions.len(),
        module.global_variables.len(),
        info
    );
    FailureTrace { text }
}

pub fn load_bind_result_log(path: &str) -> Vec<BindResultEntry> {
    let mut entries = Vec::new();
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(entry) = serde_json::from_str(&line) {
                entries.push(entry);
            }
        }
    }
    entries
}
