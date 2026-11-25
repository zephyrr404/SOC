(function () {
  "use strict";

  var script = document.currentScript;
  if (!script) return;
  var key = script.getAttribute("data-soc-key");
  var host = (script.getAttribute("data-soc-host") || window.location.origin).replace(/\/+$/, "");
  if (!key) return;

  var user = null;
  var seq = 0;
  var queue = [];
  var inFlight = false;
  var flushTimer = null;
  var lastNavAt = 0;
  var nativeFetch = window.fetch;

  var visitId = (function () {
    var v = "soc_visit";
    try {
      var id = localStorage.getItem(v);
      if (!id) {
        id = "v" + Math.random().toString(36).slice(2) + Date.now().toString(36);
        localStorage.setItem(v, id);
      }
      return id;
    } catch (e) {
      return "v" + Date.now().toString(36);
    }
  })();

  var pageLoadAt = Date.now();

  // -------------------------------------------------------------------------
  // Sensitive-field policy (do NOT "improve" this without reading the notes).
  //
  // Password-like field VALUES are never captured — neither here nor on the
  // backend. The ingest endpoint runs a matching denylist redactor over every
  // event before it is persisted, but this client-side guard is the first
  // line: values of password/token/card/etc. fields are dropped before they
  // even leave the page. Field names, types, fill status and lengths are
  // useful interaction metrics; the values are not. Sending secrets into a
  // SOC pipeline would create a second copy of credentials with weaker
  // controls than the app that owns them — there is no legitimate need.
  // -------------------------------------------------------------------------
  var SENSITIVE_NAME_RE = /(password|passwd|pass|pwd|token|secret|card|cvv|ssn|otp|api[_-]?key)/i;

  function isSensitiveName(name) {
    return SENSITIVE_NAME_RE.test(String(name || ""));
  }

  function sensitiveType(type, autocomplete) {
    var ac = String(autocomplete || "").toLowerCase();
    return type === "password" || ac.indexOf("password") !== -1 || ac.indexOf("cc-") === 0;
  }

  function redactValue(val) {
    if (val === null || val === undefined) return val;
    if (Array.isArray(val)) return val.slice(0, 50).map(redactValue);
    if (typeof val === "object") {
      var out = {};
      var keys = Object.keys(val);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        out[k] = isSensitiveName(k) ? "[REDACTED]" : redactValue(val[k]);
      }
      return out;
    }
    return typeof val === "string" ? val.slice(0, 500) : val;
  }

  function fieldValue(el) {
    if (sensitiveType(el.type, el.autocomplete) || isSensitiveName(el.name) || isSensitiveName(el.id)) return null;
    return String(el.value || "").slice(0, 200);
  }

  var sessionId = (function () {
    var v = "soc_session";
    try {
      var id = sessionStorage.getItem(v);
      if (!id) {
        id = "s" + Math.random().toString(36).slice(2) + Date.now().toString(36);
        sessionStorage.setItem(v, id);
      }
      return id;
    } catch (e) {
      return "s" + Date.now().toString(36);
    }
  })();

  function baseEvent(type, raw) {
    seq += 1;
    return {
      event_type: type,
      source: "website",
      timestamp: new Date().toISOString(),
      user: user,
      session: { session_id: sessionId, visit_id: visitId, seq: seq },
      page: {
        url: location.href,
        path: location.pathname + location.search,
        title: document.title,
        referrer: document.referrer
      },
      raw: raw
    };
  }

  function enqueue(type, raw) {
    if (queue.length >= 500) queue.shift();
    queue.push(baseEvent(type, raw));
    scheduleFlush();
  }

  function scheduleFlush() {
    if (flushTimer !== null) return;
    flushTimer = window.setTimeout(function () {
      flushTimer = null;
      void flush();
    }, 500);
  }

  function flush() {
    if (inFlight || queue.length === 0) return;
    inFlight = true;
    var events = queue.splice(0, queue.length);
    var payload = JSON.stringify({ api_key: key, events: events });
    (nativeFetch || fetch)(host + "/ingest/event", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": key },
      body: payload,
      keepalive: true
    }).catch(function () {
      queue.unshift.apply(queue, events);
    }).finally(function () {
      inFlight = false;
      if (queue.length > 0) scheduleFlush();
    });
  }

  window.addEventListener("pagehide", function () {
    if (queue.length === 0 || !navigator.sendBeacon) return;
    var events = queue.splice(0, queue.length);
    try {
      navigator.sendBeacon(
        host + "/ingest/event",
        new Blob([JSON.stringify({ api_key: key, events: events })], { type: "application/json" })
      );
    } catch (e) {}
  });

  function closest(el, fn) {
    while (el && el !== document && el !== window) {
      if (fn(el)) return el;
      el = el.parentElement;
    }
    return null;
  }

  function visibleText(el, max) {
    return (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim().slice(0, max || 120);
  }

  function pushPageView(extra) {
    var now = Date.now();
    if (now - lastNavAt < 300) return;
    lastNavAt = now;
    var raw = { entry_page: true, navigation: false };
    if (extra) {
      raw.from = extra.from;
      raw.to = extra.to;
      raw.navigation = true;
    }
    enqueue("page_view", raw);
  }

  pushPageView();

  var historyWrap = function (fn) {
    return function () {
      var prev = location.href;
      var ret = fn.apply(this, arguments);
      if (prev !== location.href) pushPageView({ from: prev, to: location.href });
      return ret;
    };
  };
  try {
    history.pushState = historyWrap(history.pushState);
    history.replaceState = historyWrap(history.replaceState);
    window.addEventListener("popstate", function () {
      pushPageView({ from: history.state && history.state.soc_prev || "", to: location.href });
    });
  } catch (e) {}

  document.addEventListener(
    "click",
    function (e) {
      var el = closest(e.target, function (n) {
        return Boolean(n.id) || /^(A|BUTTON|INPUT|SELECT|TEXTAREA|LABEL)$/.test(n.tagName);
      });
      if (!el) return;
      var cls = [];
      if (typeof el.className === "string") cls = el.className.split(/\s+/).filter(Boolean).slice(0, 5);
      var raw = {
        tag: el.tagName.toLowerCase(),
        id: el.id || "",
        classes: cls,
        text: el.id ? "" : visibleText(el, 100),
        href: typeof el.href === "string" ? el.href : "",
        name: el.name || "",
        type: el.type || "",
        value: fieldValue(el),
        x: e.clientX,
        y: e.clientY
      };
      enqueue("click", raw);
    },
    true
  );

  var inputTimers = {};
  document.addEventListener(
    "input",
    function (e) {
      var el = e.target;
      if (!el || el.tagName !== "INPUT" && el.tagName !== "TEXTAREA" && el.tagName !== "SELECT") return;
      if (!el.name && !el.id) return;
      var fieldKey = el.name || el.id;
      if (inputTimers[fieldKey]) window.clearTimeout(inputTimers[fieldKey]);
      inputTimers[fieldKey] = window.setTimeout(function () {
        delete inputTimers[fieldKey];
        var value = fieldValue(el);
        enqueue("input", {
          field: fieldKey,
          form: el.form ? el.form.id || el.form.name || el.form.action || "" : "",
          type: el.type || el.tagName.toLowerCase(),
          // Only non-sensitive values leave the page (see fieldValue).
          value: value,
          length: el.value.length,
          filled: el.value.length > 0
        });
      }, 800);
    },
    true
  );

  // Client-side validation messages (e.g. "Invalid email format") — useful
  // UX/signal data with zero sensitive content. 'invalid' events do not
  // bubble, so they are caught in the capture phase, keyed by form.
  var validationByForm = {};
  document.addEventListener(
    "invalid",
    function (e) {
      var el = e.target;
      if (!el || !el.form) return;
      var formKey = el.form.id || el.form.name || el.form.action || "";
      var msgs = validationByForm[formKey] || (validationByForm[formKey] = []);
      var msg = el.validationMessage || "Invalid value";
      var name = el.name || el.id || "";
      if (!msgs.some(function (m) { return m.field === name && m.message === msg; })) {
        msgs.push({ field: name, message: msg });
        if (msgs.length > 10) msgs.shift();
      }
      enqueue("form_invalid", {
        form: { id: el.form.id || "", name: el.form.name || "", action: el.form.action || "" },
        validation_errors: msgs.slice()
      });
    },
    true
  );

  document.addEventListener(
    "submit",
    function (e) {
      var f = e.target;
      if (!f || f.tagName !== "FORM") return;
      var formKey = f.id || f.name || f.action || "";
      var validation_errors = (validationByForm[formKey] || []).slice();
      delete validationByForm[formKey];
      var fields = [];
      for (var i = 0; i < (f.elements || []).length; i++) {
        var el = f.elements[i];
        if (!el.name) continue;
        var type = el.type || el.tagName.toLowerCase();
        var sensitive = sensitiveType(type, el.autocomplete) || isSensitiveName(el.name) || isSensitiveName(el.id);
        var entry = {
          name: el.name,
          type: type,
          // Values of sensitive fields are never sent (see the policy note
          // above); the backend redacts them again as defense in depth.
          value: sensitive ? null : fieldValue(el),
          length: el.value ? el.value.length : 0,
          filled: Boolean(el.value),
          sensitive: sensitive
        };
        fields.push(entry);
      }
      enqueue("form_submit", {
        form: { id: f.id || "", name: f.name || "", action: f.action || "", method: (f.method || "get").toUpperCase() },
        fields: fields,
        validation_errors: validation_errors,
        // Page load → submit, in ms (bot/automation signal).
        timing_ms: Date.now() - pageLoadAt
      });
    },
    true
  );

  if (nativeFetch) {
    window.fetch = function (input, init) {
      var t0 = performance.now();
      var url = typeof input === "string" ? input : input && input.url ? input.url : "";
      var method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
      var body = null;
      if (init && init.body) {
        try {
          body = redactValue(JSON.parse(init.body));
        } catch (e) {
          body = String(init.body).slice(0, 500);
        }
      }
      return nativeFetch.apply(this, arguments).then(
        function (res) {
          enqueue("fetch", {
            method: method,
            url: url.slice(0, 2000),
            status: res.status,
            ok: res.ok,
            request_body: body,
            duration_ms: Math.round(performance.now() - t0)
          });
          return res;
        },
        function (err) {
          enqueue("api_error", {
            method: method,
            url: url.slice(0, 2000),
            request_body: body,
            error: String(err && err.message || err).slice(0, 300),
            duration_ms: Math.round(performance.now() - t0)
          });
          throw err;
        }
      );
    };
  }

  window.addEventListener("error", function (e) {
    enqueue("js_error", {
      message: String(e.message || "Unhandled error").slice(0, 300),
      stack: (e.error && e.error.stack || "").slice(0, 2000),
      url: location.href
    });
  });

  window.addEventListener("unhandledrejection", function (e) {
    var reason = e.reason;
    enqueue("js_error", {
      message: String(reason && reason.message || reason || "Unhandled rejection").slice(0, 300),
      stack: reason instanceof Error ? reason.stack.slice(0, 2000) : "",
      url: location.href
    });
  });

  window.SOC = {
    identify: function (u) {
      user = u && typeof u === "object" ? { id: u.id, email: u.email, name: u.name, role: u.role } : null;
      enqueue("identify", { id: user ? user.id : null, email: user ? user.email : null, name: user ? user.name : null, role: user ? user.role : null });
    },
    logout: function () {
      user = null;
      enqueue("user_logout", {});
    },
    track: function (type, raw) {
      enqueue(String(type), raw || {});
    }
  };
})();
