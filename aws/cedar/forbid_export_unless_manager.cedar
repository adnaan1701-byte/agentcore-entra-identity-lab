// Bulk export is for managers only. forbid always wins over permit.
// Entra puts app roles in the `roles` claim; AgentCore exposes JWT claims as principal tags.
forbid(
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"docs___export_all_records",
  resource == AgentCore::Gateway::"{GATEWAY_ARN}"
) unless {
  principal.hasTag("roles") &&
  principal.getTag("roles") like "*Manager*"
};
