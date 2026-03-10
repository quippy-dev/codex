use clap::Parser;
use codex_arg0::Arg0DispatchPaths;
use codex_arg0::arg0_dispatch_or_else;
use codex_mcp_server::run_main;
use codex_utils_cli::CliConfigOverrides;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct McpServerArgs {
    /// Override the auth storage location used by MCP server auth flows.
    /// Must point to an `auth.json` path.
    #[arg(long = "auth-file", value_name = "PATH")]
    auth_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|arg0_paths: Arg0DispatchPaths| async move {
        let args = McpServerArgs::parse();
        run_main(arg0_paths, CliConfigOverrides::default(), args.auth_file).await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::McpServerArgs;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn standalone_mcp_server_parses_auth_file_override() {
        let args = McpServerArgs::parse_from(["codex-mcp-server", "--auth-file", "/tmp/auth.json"]);
        assert_eq!(args.auth_file, Some(PathBuf::from("/tmp/auth.json")));
    }
}
