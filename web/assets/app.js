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
      return "http://localhost:8010";
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
    aptReport: {
      simulation: {
        name: "APT28",
        mode: "直接 TTP",
        event_count: 10,
        node_count: 12,
        edge_count: 13,
      },
      attack_chain_signature: ["AUTHENTICATION_LOGIN", "FILE_WRITE", "NETWORK_Outbound", "PROCESS"],
      attack_chain_structure: [
        { source_type: "host", source: "PC-1", relation: "host_network", target_type: "network", target: "45.33.2.1" },
        { source_type: "host", source: "PC-1", relation: "host_auth", target_type: "network", target: "45.33.2.1" },
        {
          source_type: "process",
          source: "Parent:3000",
          relation: "spawned",
          target_type: "process",
          target: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
        {
          source_type: "process",
          source: "Parent:3000",
          relation: "spawned",
          target_type: "process",
          target: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_network",
          target_type: "network",
          target: "https:45.33.2.1:443",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_auth",
          target_type: "network",
          target: "https:45.33.2.1:443",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_file",
          target_type: "file",
          target: "C:\\Users\\Public\\Documents\\T1110.003.txt",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_file",
          target_type: "file",
          target: "C:\\Users\\Public\\Documents\\T1036.005.txt",
        },
        {
          source_type: "process",
          source: "Parent:3000",
          relation: "spawned",
          target_type: "process",
          target: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_network",
          target_type: "network",
          target: "https:198.51.100.23:443",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_auth",
          target_type: "network",
          target: "https:198.51.100.23:443",
        },
        {
          source_type: "process",
          source: "Parent:3000",
          relation: "spawned",
          target_type: "process",
          target: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
        {
          source_type: "host",
          source: "PC-1",
          relation: "host_file",
          target_type: "file",
          target: "C:\\Users\\Public\\Documents\\T1021.002.txt",
        },
      ],
      ttp_attribution: {
        suspected_group: "APT28",
        confidence: 0.733,
        matched_ttps: [
          "T1036.005",
          "T1021.002",
          "T1078",
          "T1030",
          "T1546.015",
          "T1037.001",
          "T1596",
          "T1110.003",
          "T1598",
          "T1584.008",
        ],
        jaccard_similarity: 0.11,
        recall: 1.0,
        top_matches: [
          {
            group: "APT28",
            score: 0.733,
            matched_ttps: [
              "T1036.005",
              "T1021.002",
              "T1078",
              "T1030",
              "T1546.015",
              "T1037.001",
              "T1596",
              "T1110.003",
              "T1598",
              "T1584.008",
            ],
          },
          {
            group: "Chimera",
            score: 0.298,
            matched_ttps: ["T1078", "T1036.005", "T1021.002", "T1110.003"],
          },
          {
            group: "APT41",
            score: 0.294,
            matched_ttps: ["T1078", "T1036.005", "T1021.002", "T1030"],
          },
          {
            group: "Lazarus Group",
            score: 0.292,
            matched_ttps: ["T1078", "T1036.005", "T1021.002", "T1110.003"],
          },
          {
            group: "Play",
            score: 0.237,
            matched_ttps: ["T1078", "T1030", "T1021.002"],
          },
        ],
      },
      apt_profile: {
        name: "APT28",
        aliases: [
          "APT28",
          "IRON TWILIGHT",
          "SNAKEMACKEREL",
          "Swallowtail",
          "Group 74",
          "Sednit",
          "Sofacy",
          "Pawn Storm",
          "Fancy Bear",
          "STRONTIUM",
          "Tsar Team",
          "Threat Group-4127",
          "TG-4127",
          "Forest Blizzard",
          "FROZENLAKE",
          "GruesomeLarch",
        ],
        ttps: [
          "T1584.008",
          "T1021.002",
          "T1005",
          "T1068",
          "T1037.001",
          "T1119",
          "T1583.001",
          "T1564.003",
          "T1090.003",
          "T1564.001",
          "T1003.003",
          "T1056.001",
          "T1092",
          "T1559.002",
          "T1057",
          "T1547.001",
          "T1546.015",
          "T1025",
          "T1071.001",
          "T1204.001",
        ],
        target_industries: [],
      },
      ioc_enrichment: {
        "45.33.2.1": {
          type: "ip",
          risk_score: 90,
          tags: ["C2", "Botnet", "模拟攻击"],
          geo: "Lab",
          source: "local_custom",
          is_malicious: true,
        },
        "59.64.129.102": {
          type: "ip",
          risk_score: 80,
          tags: ["Attacker", "BruteForce", "SSH", "模拟攻击"],
          geo: "Simulated Attacker",
          source: "local_custom",
          is_malicious: true,
        },
        "203.0.113.99": {
          type: "ip",
          risk_score: 65,
          tags: ["Scanner", "Recon", "模拟攻击"],
          geo: "Lab",
          source: "local_custom",
          is_malicious: false,
        },
        "198.51.100.23": {
          type: "ip",
          risk_score: 78,
          tags: ["Exfiltration", "HTTP-POST", "模拟攻击"],
          geo: "Lab",
          source: "local_custom",
          is_malicious: true,
        },
      },
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
      if (fallback !== undefined) {
        return fallback;
      }
      return { error: err?.message || "Network error" };
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
