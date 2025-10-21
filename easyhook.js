(function(global) {
  "use strict";


  const FRIDA_EXEC = (function() {
    // try to detect likely host functions exposed by H5GG
    if (typeof h5gg !== "undefined") {
      if (typeof h5gg.callNative === "function") return "h5gg.callNative"; // we'll call this specially
      if (typeof h5gg.eval === "function") return "h5gg.eval";
    }
    // common plugin-level globals some builds create
    if (typeof frida_eval === "function") return "frida_eval";
    if (typeof frida_exec === "function") return "frida_exec";
    // fallback - will attempt h5gg.callNative with a guessed symbol
    return "h5gg.callNative";
  })();


  function hostEval(code) {
    // prefer h5gg.callNative if available
    if (typeof h5gg !== "undefined" && typeof h5gg.callNative === "function") {
      try {
    
        return h5gg.callNative("frida_eval", code);
      } catch (e) {
        // some builds support h5gg.eval or h5gg.callNative("eval", code)
        try { return h5gg.eval(code); } catch(_) {}
      }
    }

    // if there is a global function like frida_eval/frida_exec call it
    if (typeof global.frida_eval === "function") {
      return global.frida_eval(code);
    }
    if (typeof global.frida_exec === "function") {
      return global.frida_exec(code);
    }

    // last resort: try calling the raw symbol name via callNative (name may vary)
    if (typeof h5gg !== "undefined" && typeof h5gg.callNative === "function") {
      try {
        return h5gg.callNative("frida_exec", code);
      } catch (e) {
        throw new Error("easyhook: host evaluation failed (no frida bridge found). Edit FRIDA_EXEC if needed.");
      }
    }

    throw new Error("easyhook: no host frida bridge available (frida_eval, frida_exec or h5gg.callNative).");
  }

  // Small utility: normalize input (number, hex string, 'module!symbol', 'module:offset')
  function normalizeAddressSpec(spec) {
    if (typeof spec === "number") return spec >>> 0;
    if (typeof spec === "string") {
      spec = spec.trim();
      // hex literal
      if (/^0x[0-9a-fA-F]+$/.test(spec)) return parseInt(spec, 16) >>> 0;
      // module!symbol pattern
      if (spec.includes("!")) {
        // ask Frida to resolve symbol: Module.findExportByName("module","symbol")
        const parts = spec.split("!");
        const module = parts[0] || null;
        const symbol = parts[1];
        const js = `({__r: (function(){ try { var a = Module.findExportByName("${escapeQuotes(module)}","${escapeQuotes(symbol)}"); return a ? ptr(a).toString() : null; } catch(e){ return null; } })()})`;
        const res = hostEval(js);
        try {
          const parsed = JSON.parse(res);
          if (parsed && parsed.__r) return parseInt(parsed.__r, 16) >>> 0;
        } catch(e){}
        // fallback: return 0
        return 0;
      }
      // module:0xoffset pattern
      if (spec.includes(":")) {
        const [mod, offStr] = spec.split(":");
        // ask Frida for base of module, then add offset
        const js = `({__r:(function(){ try{ var m = Process.findModuleByName("${escapeQuotes(mod)}"); if(!m) return null; var off = ${NumberOrHex(offStr)}; return (m.base.add(ptr(off))).toString(); }catch(e){return null}})()})`;
        const res = hostEval(js);
        try {
          const parsed = JSON.parse(res);
          if (parsed && parsed.__r) return parseInt(parsed.__r, 16) >>> 0;
        } catch(e){}
        return 0;
      }
      // plain name -> try to resolve symbol in main module
      {
        const js = `({__r:(function(){ try{ var a = Module.findExportByName(null,"${escapeQuotes(spec)}"); return a ? ptr(a).toString() : null; }catch(e){return null}})()})`;
        const res = hostEval(js);
        try {
          const parsed = JSON.parse(res);
          if (parsed && parsed.__r) return parseInt(parsed.__r, 16) >>> 0;
        } catch(e){}
      }
    }
    throw new Error("easyhook: unsupported spec: " + String(spec));
  }

  // helper: convert "0x..." or decimal string to numeric expression used inside injected code
  function NumberOrHex(s) {
    s = (s || "").trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s, 16);
    const n = Number(s);
    if (!isNaN(n)) return n;
    return 0;
  }

  function escapeQuotes(s) {
    if (s == null) return "";
    return String(s).replace(/\\/g,"\\\\").replace(/"/g,"\\\"");
  }

  // Wrapper object produced by hook()
  function AddrWrapper(addr) {
    // store numeric address
    this._addr = (addr >>> 0);
  }
  AddrWrapper.prototype.toString = function() {
    return "0x" + this._addr.toString(16);
  };
  AddrWrapper.prototype.valueOf = function() {
    return this._addr;
  };
  // convenience: add offset -> returns new AddrWrapper
  AddrWrapper.prototype.add = function(off) {
    const offN = Number(off) >>> 0;
    return new AddrWrapper((this._addr + offN) >>> 0);
  };
  // attach Interceptor to this address (handler is an object with onEnter/onLeave)
  AddrWrapper.prototype.intercept = function(handler) {
    if (!handler) throw new Error("easyhook.intercept: missing handler");
    const onEnterExists = typeof handler.onEnter === "function";
    const onLeaveExists = typeof handler.onLeave === "function";
    // build frida JS to evaluate
    const injected = `
      (function(){
        try {
          var target = ptr("${this.toString()}");
          Interceptor.attach(target, {
            onEnter: ${onEnterExists ? handler.onEnter.toString() : "undefined"},
            onLeave: ${onLeaveExists ? handler.onLeave.toString() : "undefined"}
          });
          return JSON.stringify({ok:true});
        } catch(e) { return JSON.stringify({ok:false, error: String(e)}); }
      })();
    `;
    const res = hostEval(injected);
    let parsed;
    try { parsed = JSON.parse(res); } catch(e) { parsed = { ok:false, error:res }; }
    if (!parsed.ok) throw new Error("easyhook.intercept error: " + (parsed.error || "unknown"));
    return true;
  };

  // Shortcut: intercept(addrOrSpec, handler)
  function intercept(addrOrSpec, handler) {
    const aw = hook(addrOrSpec);
    return aw.intercept(handler);
  }

  // Hook resolver: returns an AddrWrapper
  function hook(spec) {
    // allow already an AddrWrapper
    if (spec && spec._addr !== undefined) return spec;
    // allow raw number
    if (typeof spec === "number") return new AddrWrapper(spec >>> 0);
    // try to resolve via host (Module.findExportByName / Process.findModuleByName)
    const addr = normalizeAddressSpec(spec);
    return new AddrWrapper(addr);
  }

  // Convenience: scan memory for a byte pattern (frida style "12 34 ?? 56")
  function scan(moduleOrRange, pattern, callbackName) {
    // If moduleOrRange is a module name, use Module.findBaseAddress
    const js = `
      (function(){
        try {
          var mod = Process.findModuleByName("${escapeQuotes(moduleOrRange)}");
          if(!mod) return JSON.stringify({ok:false, error:"module not found"});
          var results = [];
          Memory.scan(mod.base, mod.size, "${escapeQuotes(pattern)}", { onMatch: function(addr, size) {
              results.push(ptr(addr).toString());
            }, onComplete: function(){} });
          return JSON.stringify({ok:true, matches:results});
        } catch(e){ return JSON.stringify({ok:false, error:String(e)}); }
      })();
    `;
    const res = hostEval(js);
    let parsed;
    try { parsed = JSON.parse(res); } catch(e) { parsed = {ok:false, error:res}; }
    if (!parsed.ok) throw new Error("easyhook.scan: " + (parsed.error || "unknown"));
    return parsed.matches.map(m => new AddrWrapper(parseInt(m, 16) >>> 0));
  }

  // Exported API
  const easyhook = {
    hook,
    intercept,
    scan,
    AddrWrapper,
    hostEval,
    _FRIDA_BRIDGE: FRIDA_EXEC
  };

  // Attach to global
  if (typeof module !== "undefined" && module.exports) {
    module.exports = easyhook;
  } else {
    global.easyhook = easyhook;
  }

})(this);
