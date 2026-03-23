package agentic.policy

import rego.v1

# Default policy: allow everything except curl to IP addresses.
# This is a trivial example to demonstrate the interceptor.

decision := {"decision": "deny", "reason": "curl to IP address is not allowed"} if {
	input.tool_name == "Bash"
	contains(input.parameters.command, "curl")
	regex.match(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, input.parameters.command)
}
