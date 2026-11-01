// Download names come from the sender, so the browser is handed something harmless
// (SPEC §10): no controls, no bidi tricks, nothing that reads as a path, nothing a filesystem
// refuses, and not too long. Shown and used for the download alike.

// Windows device names, with or without an extension.
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
// Controls, bidi overrides/isolates/marks, zero-width and BOM characters, line separators.
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
// Path separators and their look-alikes, plus what Windows refuses in a name.
const SEPARATORS = /[/\\\u2044\u2215\u29f5\u29f8\u29f9\uff0f\uff3c:*?"<>|]/g;
const MAX_BYTES = 255;

export function sanitiseFileName(name: string): string {
  let out = name.normalize("NFC").replace(INVISIBLE, "").replace(SEPARATORS, "_");
  // Leading dots hide a file or point up the tree; trailing dots and spaces are dropped by Windows.
  out = out.replace(/^[. ]+/, "").replace(/[. ]+$/, "");
  if (RESERVED.test(out)) out = `_${out}`;
  return truncate(out) || "file";
}

// Cuts to the common 255-byte filesystem limit on a character boundary.
function truncate(name: string): string {
  const encoder = new TextEncoder();
  if (encoder.encode(name).length <= MAX_BYTES) return name;
  let out = "";
  for (const ch of name) {
    if (encoder.encode(out + ch).length > MAX_BYTES) break;
    out += ch;
  }
  return out;
}
