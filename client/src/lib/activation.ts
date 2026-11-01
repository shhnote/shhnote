// Only a real press may reveal a secret (SPEC §5). A page script can fire a trusted
// `submit` (`requestSubmit()`) or a trusted `click` with `detail` 0 (`button.click()`), so
// neither counts: a pointer click with `detail > 0` or a key press, both trusted, and only
// while the browser reports user activation (browsers without the API are not asked).
export function isUserActivation(event: Event): boolean {
  if (!event.isTrusted || !userActivated()) return false;
  if (event.type === "click") return (event as MouseEvent).detail > 0;
  if (event.type === "keydown") {
    const key = (event as KeyboardEvent).key;
    return key === "Enter" || key === " ";
  }
  return false;
}

function userActivated(): boolean {
  if (typeof navigator === "undefined") return true;
  const activation = (navigator as { userActivation?: { isActive: boolean } }).userActivation;
  return activation === undefined || activation.isActive;
}
