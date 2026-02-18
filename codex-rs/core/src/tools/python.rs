use crate::client_common::tools::ResponsesApiTool;
use crate::client_common::tools::ToolSpec;
use crate::tools::handlers::PythonHandler;
use crate::tools::registry::ToolRegistryBuilder;
use crate::tools::spec::JsonSchema;
use crate::tools::spec::create_approval_parameters;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) fn register_python_tool(builder: &mut ToolRegistryBuilder, include_prefix_rule: bool) {
    let python_handler = Arc::new(PythonHandler);
    builder.push_spec_with_parallel_support(create_python_tool(include_prefix_rule), true);
    builder.register_handler("python", python_handler);
}

fn create_python_tool(include_prefix_rule: bool) -> ToolSpec {
    let mut properties = BTreeMap::from([
        (
            "code".to_string(),
            JsonSchema::String {
                description: Some("Python source code to execute with `python3 -c`.".to_string()),
            },
        ),
        (
            "args".to_string(),
            JsonSchema::Array {
                items: Box::new(JsonSchema::String { description: None }),
                description: Some(
                    "Optional command line arguments passed to the script as `sys.argv[1:]`."
                        .to_string(),
                ),
            },
        ),
        (
            "python".to_string(),
            JsonSchema::String {
                description: Some(
                    "Optional Python executable path. Defaults to `python3`.".to_string(),
                ),
            },
        ),
        (
            "workdir".to_string(),
            JsonSchema::String {
                description: Some(
                    "Optional working directory to run the command in; defaults to the turn cwd."
                        .to_string(),
                ),
            },
        ),
        (
            "timeout_ms".to_string(),
            JsonSchema::Number {
                description: Some(
                    "Maximum runtime in milliseconds before the process is terminated.".to_string(),
                ),
            },
        ),
    ]);
    properties.extend(create_approval_parameters(include_prefix_rule));

    ToolSpec::Function(ResponsesApiTool {
        name: "python".to_string(),
        description: "Run a Python snippet in a subprocess and return stdout/stderr.".to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["code".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}
