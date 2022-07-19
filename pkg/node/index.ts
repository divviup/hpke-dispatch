import wasm from "./hpke_dispatch_bg.wasm";
import init from "./hpke_dispatch.js";
//this is exported so it doesn't get dead-code-eliminated
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
export const __wasm = init(wasm);
export * from "./hpke_dispatch.js";
