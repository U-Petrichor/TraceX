(() => {
  const storageKey = "tracex_api_base";
  const saved = (() => {
    try {
      return localStorage.getItem(storageKey);
    } catch (err) {
      return null;
    }
  })();

  const defaultApi = (() => {
    if (window.TRACEX_API) {
      return window.TRACEX_API;
    }
    if (saved) {
      return saved;
    }
    if (window.location.protocol === "file:") {
      return "http://localhost:8000";
    }
    return window.location.origin;
  })();

  const state = {
    apiBase: defaultApi,
    offline: false,
  };

  const sample = {
    stats: { total_events: 148233, threat_count: 239, period_hours: 24 },
    trend: {
      data: [
        { time: "2024-01-10T00:00:00Z", count: 1200 },
        { time: "2024-01-10T04:00:00Z", count: 980 },
        { time: "2024-01-10T08:00:00Z", count: 1320 },
        { time: "2024-01-10T12:00:00Z", count: 1640 },
        { time: "2024-01-10T16:00:00Z", count: 1880 },
        { time: "2024-01-10T20:00:00Z", count: 1430 },
        { time: "2024-01-11T00:00:00Z", count: 1710 },
      ],
    },
    attacks: {
      attacks: [
        {
          "@timestamp": "2024-01-11T01:12:41Z",
          event: { category: "process", dataset: "auditd", action: "exec" },
          host: { name: "web-node-01" },
          source: { ip: "172.20.0.20" },
          destination: { ip: "203.0.113.32" },
          process: { name: "bash", command_line: "curl | sh" },
          user: { name: "www-data" },
          threat: {
            tactic: { name: "执行" },
            technique: { name: "命令与脚本" },
            confidence: 0.82,
          },
          detection: { severity: "high", rules: ["可疑 Shell"] },
        },
        {
          "@timestamp": "2024-01-11T02:18:07Z",
          event: { category: "network", dataset: "zeek.conn", action: "connect" },
          host: { name: "db-node-02" },
          source: { ip: "198.51.100.44" },
          destination: { ip: "172.20.0.31" },
          threat: {
            tactic: { name: "初始访问" },
            technique: { name: "利用公开应用" },
            confidence: 0.76,
          },
          detection: { severity: "medium", rules: ["Web 漏洞利用"] },
        },
        {
          "@timestamp": "2024-01-11T03:42:29Z",
          event: { category: "authentication", dataset: "cowrie", action: "login" },
          host: { name: "honeypot-01" },
          source: { ip: "203.0.113.70" },
          destination: { ip: "172.20.0.77" },
          user: { name: "root" },
          threat: {
            tactic: { name: "凭证访问" },
            technique: { name: "暴力破解" },
            confidence: 0.91,
          },
          detection: { severity: "high", rules: ["SSH 暴力破解"] },
        },
      ],
    },
    logs: {
      data: [
        {
          "@timestamp": "2024-01-11T03:42:29Z",
          event: { dataset: "cowrie", category: "authentication" },
          message: "SSH 登录尝试 来自 203.0.113.70",
          source: { ip: "203.0.113.70" },
          host: { name: "honeypot-01" },
          user: { name: "root" },
        },
        {
          "@timestamp": "2024-01-11T02:18:07Z",
          event: { dataset: "zeek.conn", category: "network" },
          message: "可疑外联连接",
          source: { ip: "198.51.100.44" },
          destination: { ip: "172.20.0.31" },
          host: { name: "db-node-02" },
        },
        {
          "@timestamp": "2024-01-11T01:12:41Z",
          event: { dataset: "auditd", category: "process" },
          message: "进程启动并携带编码载荷",
          process: { name: "bash" },
          host: { name: "web-node-01" },
        },
      ],
      total: 3,
      page: 1,
      size: 3,
    },
  };

  const safeGet = (obj, path, fallback = "-") => {
    if (!obj || !path) {
      return fallback;
    }
    const parts = path.split(".");
    let current = obj;
    for (const part of parts) {
      if (current && Object.prototype.hasOwnProperty.call(current, part)) {
        current = current[part];
      } else {
        return fallback;
      }
    }
    return current == null || current === "" ? fallback : current;
  };

  const formatNumber = (value) => {
    if (value == null || Number.isNaN(value)) {
      return "-";
    }
    try {
      return new Intl.NumberFormat("zh-CN", { notation: "compact" }).format(value);
    } catch (err) {
      return String(value);
    }
  };

  const formatTime = (value) => {
    if (!value) {
      return "-";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return "-";
    }
    // Convert to Beijing Time (UTC+8)
    return new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })
      .format(date)
      .replace(/\//g, "-");
  };

  const setStatus = (label, tone) => {
    const text = document.querySelector(".js-status");
    if (text) {
      text.textContent = label;
    }
    const pill = document.querySelector(".status-pill");
    if (pill) {
      pill.dataset.tone = tone || "live";
    }
  };

  const fetchJson = async (path, fallback) => {
    const base = state.apiBase.endsWith("/") ? state.apiBase.slice(0, -1) : state.apiBase;
    const url = path.startsWith("http") ? path : `${base}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);
    try {
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) {
        throw new Error(`Request failed: ${res.status}`);
      }
      const data = await res.json();
      state.offline = false;
      setStatus("在线", "live");
      return data;
    } catch (err) {
      state.offline = true;
      setStatus("离线演示", "offline");
      return fallback;
    }
  };

  const initNav = () => {
    const page = document.body.dataset.page;
    const links = document.querySelectorAll(".nav a");
    links.forEach((link) => {
      link.dataset.active = link.dataset.nav === page ? "true" : "false";
    });
  };

  const initPanel = () => {
    const toggle = document.querySelector("[data-toggle-panel]");
    const panel = document.querySelector("[data-panel]");
    const closeBtn = document.querySelector("[data-panel-close]");
    const input = document.querySelector("#apiBaseInput");
    const save = document.querySelector("#apiBaseSave");

    const setPanelOpen = (open) => {
      if (!panel) {
        return;
      }
      panel.hidden = !open;
      panel.dataset.open = open ? "true" : "false";
      if (toggle) {
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      }
    };

    if (input) {
      input.value = state.apiBase;
    }

    if (toggle && panel) {
      toggle.addEventListener("click", () => {
        setPanelOpen(panel.hidden);
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        setPanelOpen(false);
      });
    }

    if (save && input) {
      save.addEventListener("click", () => {
        const next = input.value.trim();
        if (!next) {
          return;
        }
        state.apiBase = next;
        try {
          localStorage.setItem(storageKey, next);
        } catch (err) {
          return;
        }
        setStatus("在线", "live");
        setPanelOpen(false);
      });
    }

    document.addEventListener("click", (event) => {
      if (!panel || panel.hidden) {
        return;
      }
      if (panel.contains(event.target) || (toggle && toggle.contains(event.target))) {
        return;
      }
      setPanelOpen(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        setPanelOpen(false);
      }
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    initNav();
    initPanel();
  });

  window.TraceX = {
    state,
    sample,
    safeGet,
    formatNumber,
    formatTime,
    setStatus,
    fetchJson,
  };
})();
