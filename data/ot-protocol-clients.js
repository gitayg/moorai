// Industrial (OT) protocol clients an agent can run from a shell, for cli/ot-protocol-client.mjs.
// Contract: CONTRACT-F28 §6.3 (reasonCode OT_PROTOCOL_CLIENT, otProtocol, otOp).
//
// Three kinds of entry:
//   OT_BINARIES   command-line tools, keyed by binary name. `op` says how the command line tells a read
//                 from a write: "values-after-target" (mbpoll, modpoll: "mbpoll [options] device|host
//                 [writevalues...]", values after the target are written), "subcommand" (modbus-cli:
//                 `modbus read|write|dump`), or a fixed "read" / "write" / "unknown" for tools that do one
//                 thing (OPC UA's uaread / uawrite, the BACnet stack's bacrp / bacwp).
//   OT_PY_LIBS    Python import names, with the method calls that read and that write.
//   OT_NODE_LIBS  Node package names, the same way.
//   OT_PY_MODULES `python -m <module>` entry points that are clients in their own right.
//
// A call list is matched as `name(` (an identifier, then an opening parenthesis), so a write in a comment
// or a string still counts: the classification is for policy, and reading a read as a write fails toward
// the stricter action. A library imported with no listed call is "unknown".
//
// Browser-safe (no node: imports): data/ is bundled by the desktop app.

export const OT_PROTOCOLS = Object.freeze(["modbus", "dnp3", "opcua", "s7", "bacnet", "enip", "iec104"]);
export const OT_OPS = Object.freeze(["read", "write", "unknown"]);

export const OT_BINARIES = Object.freeze({
  // Modbus. mbpoll / modpoll option letters that take a value (from their usage text).
  mbpoll: { protocol: "modbus", op: "values-after-target", shortValued: "matcrlopbdsP" },
  modpoll: { protocol: "modbus", op: "values-after-target", shortValued: "matcrlopbdsP" },
  modbus: { protocol: "modbus", op: "subcommand", read: ["read", "dump"], write: ["write"] },
  // OPC UA command-line tools shipped with python-opcua / asyncua.
  uaread: { protocol: "opcua", op: "read" },
  uals: { protocol: "opcua", op: "read" },
  uasubscribe: { protocol: "opcua", op: "read" },
  uahistoryread: { protocol: "opcua", op: "read" },
  uadiscover: { protocol: "opcua", op: "read" },
  uawrite: { protocol: "opcua", op: "write" },
  uacall: { protocol: "opcua", op: "write" },
  uaclient: { protocol: "opcua", op: "unknown" },
  // BACnet stack demo clients.
  bacrp: { protocol: "bacnet", op: "read" },
  bacrpm: { protocol: "bacnet", op: "read" },
  bacwi: { protocol: "bacnet", op: "read" },
  bacepics: { protocol: "bacnet", op: "read" },
  bacwp: { protocol: "bacnet", op: "write" },
  bacwpm: { protocol: "bacnet", op: "write" },
  bacrd: { protocol: "bacnet", op: "write" },
  bacdcc: { protocol: "bacnet", op: "write" }
});

// python -m <module>: the protocol, and how the arguments say read or write.
export const OT_PY_MODULES = Object.freeze({
  "cpppo.server.enip.client": { protocol: "enip", op: "tag-assign" }, // `Tag=(INT)1` writes, `Tag` reads
  "pymodbus.console": { protocol: "modbus", op: "unknown" },
  "pymodbus.repl": { protocol: "modbus", op: "unknown" }
});

const MODBUS_PY = { protocol: "modbus",
  write: ["write_register", "write_registers", "write_coil", "write_coils", "readwrite_registers", "mask_write_register", "write_single_register", "write_multiple_registers", "write_single_coil", "write_multiple_coils", "write_bit", "write_bits", "write_float", "write_long", "write_string"],
  read: ["read_holding_registers", "read_input_registers", "read_coils", "read_discrete_inputs", "read_register", "read_registers", "read_bit", "read_bits", "read_float", "read_long", "read_string"] };
const OPCUA_PY = { protocol: "opcua",
  write: ["set_value", "write_value", "set_attribute", "write_attribute", "write_values", "set_values", "call_method", "add_variable", "add_object", "delete_nodes"],
  read: ["get_value", "read_value", "read_values", "get_values", "read_attribute", "get_children", "read_browse_name", "browse"] };

export const OT_PY_LIBS = Object.freeze({
  pymodbus: MODBUS_PY,
  pyModbusTCP: MODBUS_PY,
  minimalmodbus: MODBUS_PY,
  umodbus: { protocol: "modbus", write: ["write_single_coil", "write_multiple_coils", "write_single_register", "write_multiple_registers"], read: ["read_coils", "read_discrete_inputs", "read_holding_registers", "read_input_registers"] },
  opcua: OPCUA_PY,
  asyncua: OPCUA_PY,
  snap7: { protocol: "s7",
    write: ["db_write", "write_area", "ab_write", "eb_write", "mb_write", "tm_write", "ct_write", "write_multi_vars", "plc_stop", "plc_cold_start", "plc_hot_start", "set_plc_datetime", "delete", "download"],
    read: ["db_read", "read_area", "ab_read", "eb_read", "mb_read", "tm_read", "ct_read", "read_multi_vars", "get_cpu_state", "get_cpu_info", "list_blocks", "upload"] },
  pycomm3: { protocol: "enip", write: ["write"], read: ["read", "get_tag_list", "get_plc_info"] },
  pylogix: { protocol: "enip", write: ["Write"], read: ["Read", "GetTagList", "GetPLCTime"] },
  cpppo: { protocol: "enip", write: [], read: [] },
  BAC0: { protocol: "bacnet", write: ["write", "writeMultiple"], read: ["read", "readMultiple", "whois", "discover"] },
  bacpypes: { protocol: "bacnet", write: ["WritePropertyRequest", "WritePropertyMultipleRequest"], read: ["ReadPropertyRequest", "ReadPropertyMultipleRequest", "WhoIsRequest"] },
  pydnp3: { protocol: "dnp3", write: ["DirectOperate", "SelectAndOperate"], read: ["ScanAllObjects", "ScanClasses", "ScanRange", "AddClassScan"] },
  dnp3: { protocol: "dnp3", write: ["direct_operate", "select_and_operate", "DirectOperate", "SelectAndOperate"], read: ["scan_all", "scan_classes", "scan_range", "integrity_scan"] },
  c104: { protocol: "iec104", write: ["transmit"], read: ["read"] },
  lib60870: { protocol: "iec104", write: ["send_command", "sendCommand"], read: ["interrogation", "send_interrogation"] }
});

const MODBUS_NODE = { protocol: "modbus",
  write: ["writeRegister", "writeRegisters", "writeCoil", "writeCoils", "writeSingleRegister", "writeMultipleRegisters", "writeSingleCoil", "writeMultipleCoils", "writeFC5", "writeFC6", "writeFC15", "writeFC16"],
  read: ["readHoldingRegisters", "readInputRegisters", "readCoils", "readDiscreteInputs", "readFC1", "readFC2", "readFC3", "readFC4"] };

export const OT_NODE_LIBS = Object.freeze({
  "modbus-serial": MODBUS_NODE,
  jsmodbus: MODBUS_NODE,
  "node-opcua": { protocol: "opcua", write: ["write", "writeSingleNode", "call", "writeValue"], read: ["read", "readVariableValue", "browse", "readAllAttributes"] },
  "node-opcua-client": { protocol: "opcua", write: ["write", "writeSingleNode", "call"], read: ["read", "readVariableValue", "browse"] },
  "node-snap7": { protocol: "s7", write: ["DBWrite", "ABWrite", "EBWrite", "MBWrite", "TMWrite", "CTWrite", "WriteArea", "WriteMultiVars", "PlcStop", "PlcHotStart", "PlcColdStart", "Download", "Delete"], read: ["DBRead", "ABRead", "EBRead", "MBRead", "TMRead", "CTRead", "ReadArea", "ReadMultiVars", "PlcStatus", "Upload", "ListBlocks"] },
  bacstack: { protocol: "bacnet", write: ["writeProperty", "writePropertyMultiple", "reinitializeDevice", "deviceCommunicationControl"], read: ["readProperty", "readPropertyMultiple", "whoIs"] },
  "node-bacnet": { protocol: "bacnet", write: ["writeProperty", "writePropertyMultiple", "reinitializeDevice", "deviceCommunicationControl"], read: ["readProperty", "readPropertyMultiple", "whoIs"] },
  "st-ethernet-ip": { protocol: "enip", write: ["writeTag", "writeTagGroup"], read: ["readTag", "readTagGroup"] },
  "ethernet-ip": { protocol: "enip", write: ["writeTag", "writeTagGroup"], read: ["readTag", "readTagGroup"] }
});

// Interpreters whose code (inline, heredoc or script file) is read for the libraries above.
export const PY_INTERPRETERS = /^(?:python(?:\d+(?:\.\d+)?)?w?|py|pypy3?|ipython3?)$/;
export const NODE_INTERPRETERS = /^(?:node|nodejs|bun|deno|tsx|ts-node)$/;
// Runners whose `run` subcommand starts another command (`uv run python x.py`, `poetry run x`).
export const RUNNERS = Object.freeze(["uv", "poetry", "pipenv", "pdm", "hatch", "npx", "pnpm", "yarn"]);
