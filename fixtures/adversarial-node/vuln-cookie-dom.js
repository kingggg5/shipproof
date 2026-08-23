// Adversarial recall probe: cookie value parsed (not sanitized) then rendered
// through innerHTML. Parsing does not clear taint.
function mountBadge() {
  const raw = document.cookie;
  const badge = raw.split(";")[0];
  badgeEl.innerHTML = badge;
}
