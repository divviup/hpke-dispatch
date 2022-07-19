import wasm from "./hpke_dispatch_bg.wasm";
import init from "./hpke_dispatch.js";
//this is exported so it doesn't get dead-code-eliminated
export const __wasm = init(wasm);
export * from "./hpke_dispatch.js";
