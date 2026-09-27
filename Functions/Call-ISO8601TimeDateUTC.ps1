function _CallISO8601TimeDateUTC {
  [System.String](Get-Date -Date $((Get-Date -AsUTC)) -Format "yyyy-MM-ddTHH:mm:ssZ")
}