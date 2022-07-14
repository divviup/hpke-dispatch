import wasm from "../pkg/node/hpke_dispatch_bg.wasm";
import init from "../pkg/node/hpke_dispatch.js";
//this is exported so it doesn't get dead-code-eliminated
export const __wasm = init(wasm);
export * from "../pkg/web/hpke_dispatch.js";
