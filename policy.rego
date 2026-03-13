package mcp.authz

default allow = false

# Role resolution from API key
api_key_roles := {
    "secret-admin-key": "admin",
    "secret-user-key": "viewer"
}

# Role permissions
role_tools := {
    "admin": ["*"],
    "viewer": ["fs-1_readFile", "fs-1_listDir"]
}

# Get role from API key
role := r {
    r := api_key_roles[input.api_key]
}

# Allow tool access
allow {
    input.action == "allow_tool"
    tools := role_tools[input.role]
    tools[_] == "*"
}

allow {
    input.action == "allow_tool"
    tools := role_tools[input.role]
    tools[_] == input.tool
}

# Allow function access (default allow unless explicitly denied)
allow {
    input.action == "allow_function"
}

# Get role action returns role field
allow {
    input.action == "get_role"
    api_key_roles[input.api_key]
}
