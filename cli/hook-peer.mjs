// The process the hook's parent-process checks start from. A command hook is a child of the shell the agent
// runs it in, so that is process.ppid. A warm hook worker (cli/hook-warm-worker.mjs) is a child of moorai-hookd
// instead, and is told the agent's pid, which moorai-hookd reads from the HTTP connection itself
// (cli/hook-http.mjs). Only code in the worker's own process can set it: there is no environment variable or
// file for it, so nothing that starts the command hook (an implant running `claude -p` included) can point the
// walk at another process. 0 means the agent's pid could not be read: the walk then finds nothing ("unreadable").
let PEER = null;

export function setHookPeerPid(pid) {
  PEER = Number.isSafeInteger(pid) && pid > 1 ? pid : 0;
}

export function hookPeerPid() {
  return PEER === null ? process.ppid : PEER;
}
