// Baseline: once a policy engine is attached the gateway is deny-by-default.
permit(
  principal,
  action,
  resource == AgentCore::Gateway::"{GATEWAY_ARN}"
);
