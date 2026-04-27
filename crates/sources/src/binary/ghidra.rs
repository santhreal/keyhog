use std::path::{Path, PathBuf};
use std::process::Command;

use keyhog_core::SourceError;

/// Search standard locations for Ghidra's `analyzeHeadless` script.
pub(crate) fn find_ghidra_headless() -> Option<PathBuf> {
    // Check GHIDRA_HOME env var first
    if let Ok(home) = std::env::var("GHIDRA_HOME") {
        let path = PathBuf::from(&home).join("support").join("analyzeHeadless");
        if path.exists() {
            return Some(path);
        }
    }

    // SECURITY: kimi-wave1 audit finding 3.PATH-which. Don't shell out to
    // `which` (resolved via $PATH itself) — instead enumerate trusted
    // locations directly. The `analyzeHeadless` script is shipped by
    // Ghidra, not a system binary, so we look in the standard install
    // dirs explicitly. The previous `Command::new("which")` was
    // PATH-injectable, and what `which` returned was used as the binary
    // we then exec'd, double-amplifying the injection surface.
    if let Some(which_bin) = keyhog_core::safe_bin::resolve_safe_bin("which") {
        if let Ok(output) = Command::new(&which_bin).arg("analyzeHeadless").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                // Only accept if the resolved path is absolute. Defends
                // against `which` being aliased / shimmed to print
                // attacker-controlled text.
                let pb = PathBuf::from(&path);
                if pb.is_absolute() && pb.exists() {
                    return Some(pb);
                }
            }
        }
    }

    // Common installation paths
    for pattern in &[
        "/opt/ghidra*/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "/usr/local/share/ghidra/support/analyzeHeadless",
    ] {
        for entry in glob::glob(pattern).into_iter().flatten().flatten() {
            if entry.exists() {
                return Some(entry);
            }
        }
    }

    None
}

/// Write a Ghidra postScript that runs analysis and exports decompiled C.
pub(crate) fn write_ghidra_script(
    script_path: &Path,
    output_path: &Path,
) -> Result<(), SourceError> {
    let script = format!(
        r#"// KeyHog Ghidra export script — runs full analysis then decompiles all functions.
// @category KeyHog
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends GhidraScript {{
    @Override
    public void run() throws Exception {{
        // Run full analysis first
        analyzeAll(currentProgram);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter("{output}"));

        // Export all string data from the program
        var dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {{
            var data = dataIterator.next();
            if (data.hasStringValue()) {{
                writer.println("// DATA @ " + data.getAddress() + ": " + data.getValue());
            }}
        }}

        // Decompile all functions
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        while (funcs.hasNext()) {{
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {{
                String decompiled = results.getDecompiledFunction().getC();
                if (decompiled != null) {{
                    writer.println("// FUNCTION: " + func.getName() + " @ " + func.getEntryPoint());
                    writer.println(decompiled);
                    writer.println();
                }}
            }}
        }}

        decomp.dispose();
        writer.close();
    }}
}}
"#,
        output = output_path
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );

    std::fs::write(script_path, script).map_err(SourceError::Io)
}
