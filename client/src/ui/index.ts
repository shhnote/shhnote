// `@shhnote/client/ui`: the reference page controllers. DOM only here.
export { wireBurn } from "./burn.ts";
export { wireMenus, wirePasswordToggles, wireTheme } from "./chrome.ts";
export { fillTtl, ttlChoices, wireCreate } from "./create.ts";
export {
  $,
  $$,
  COPIED_MS,
  formatDuration,
  type PageOptions,
  type PageSettings,
  apiFrom,
  argon2Url,
  hide,
  instanceValue,
  maxBlobBytesFrom,
  pageSettings,
  setState,
  setStatus,
  show,
  wireCopy,
} from "./dom.ts";
export { Dropzone, wireDropzone } from "./dropzone.ts";
export { type Strings, type Translate, type UiKey, createT } from "./i18n.ts";
export { wireReport } from "./report.ts";
export { wireReveal } from "./reveal.ts";
export { wireTabs } from "./tabs.ts";
