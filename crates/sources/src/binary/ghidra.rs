use std::path::{Path, PathBuf};

use keyhog_core::SourceError;

/// Search standard locations for Ghidra's `analyzeHeadless` script.
pub(crate) fn find_ghidra_headless() -> Option<PathBuf> {
    // Non-standard Ghidra installs belong in .keyhog.toml
    // [system].trusted_bin_dirs, never in PATH or GHIDRA_HOME. This keeps
    // decompiler execution under the same trust boundary as git/docker.
    if let Some(path) = keyhog_core::resolve_safe_bin("analyzeHeadless") {
        return Some(path);
    }

    // Common installation paths
    for pattern in &[
        "/opt/ghidra*/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "/usr/local/share/ghidra/support/analyzeHeadless",
    ] {
        let paths = match glob::glob(pattern) {
            Ok(paths) => paths,
            Err(error) => {
                tracing::warn!(
                    pattern,
                    %error,
                    "Ghidra discovery glob pattern failed; skipping pattern"
                );
                continue;
            }
        };
        for entry in paths {
            match entry {
                Ok(entry) => {
                    if entry.exists() {
                        return Some(entry);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        pattern,
                        %error,
                        "Ghidra discovery glob entry failed; skipping entry"
                    );
                }
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
        r#"// KeyHog Ghidra export script - runs full analysis then decompiles all functions.
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
