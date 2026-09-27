// An OUTBOUND UPLOAD — a command that sends a payload off the device, whatever the payload is. Not a
// detector: the hook records it as a content-free boolean per Bash call (cli/hook-core.mjs
// clipboardSignals) so a clipboard read in one call and an upload in a LATER call of the same session
// can be tied (cli/moorai-hook.mjs logBehavior). A plain GET, a download (`-o`, `-O`, `-OutFile`) and
// a port probe or listener (`nc -z`, `nc -l`) are not uploads. The curl flags are matched case-
// sensitively on purpose: `-sf` is fail-silently, `-F` is a form upload.
export const OUTBOUND_UPLOAD = [
  /(?<![\w.\/-])curl(?![\w.\/-])[^;&|\n]{0,300}?\s(?:-[a-zA-Z]{0,5}[dFT]|--(?:data(?:-binary|-raw|-urlencode|-ascii)?|form(?:-string)?|upload-file|json)|(?:-X|--request)\s{0,4}["']?(?:POST|PUT|PATCH|post|put|patch))(?=[\s=@'"]|$)/,
  /(?<![\w.\/-])wget(?![\w.\/-])[^;&|\n]{0,300}?\s--(?:post-data|post-file|body-data|body-file|method[= ]["']?(?:POST|PUT|PATCH|post|put|patch))(?![\w-])/,
  /(?<![\w.\/-])(?:nc|ncat|netcat|socat)(?=\s)(?![^;&|\n]{0,120}?(?:\s-[a-zA-Z]{0,4}[lzh](?![\w-])|listen))/i,
  /(?<![\w.\/-])(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?![\w.\/-])[^;&|\n]{0,300}?\s-(?:Body|InFile|Method\s{1,4}["']?(?:Post|Put|Patch))(?![\w-])/i
];
