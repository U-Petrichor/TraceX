(() => {
  const { fetchJson, sample, safeGet, formatTime, formatNumber } = window.TraceX;

  const els = {
    range: document.querySelector("#rangeSelect"),
    rebuildBtn: document.querySelector("#rebuildBtn"),
    nodeCount: document.querySelector("#nodeCount"),
    edgeCount: document.querySelector("#edgeCount"),
    flowList: document.querySelector("#flowList"),
    sequenceList: document.querySelector("#sequenceList"),
  };

  let graphChart;
  let animationTimer;
  let currentSteps = [];
  let currentIndex = 0;
  let isPlaying = false;
  const ANIMATION_INTERVAL = 2400;
  let playBtn;
  let pauseBtn;

  const stopAnimation = () => {
    if (animationTimer) {
      window.clearInterval(animationTimer);
      animationTimer = undefined;
    }
  };

  const initChart = () => {
    const el = document.querySelector("#graphCanvas");
    if (el && window.echarts) {
      graphChart = window.echarts.init(el);
    }
  };


  const parseTime = (event) => {
    const raw = event?.["@timestamp"];
    if (!raw) {
      return Number.POSITIVE_INFINITY;
    }
    const time = new Date(raw).getTime();
    return Number.isFinite(time) ? time : Number.POSITIVE_INFINITY;
  };

  const isIpAddress = (value) => /^(\d{1,3}\.){3}\d{1,3}$/.test(value);

  const createNode = (id, label, category, size) => ({
    id,
    name: label,
    category: isIpAddress(label) ? 1 : category,
    symbolSize: size,
  });

  const buildStepFromEvent = (event, index) => {
    const srcIp = safeGet(event, "source.ip", null);
    const dstIp = safeGet(event, "destination.ip", null);
    const host = safeGet(event, "host.name", null);
    const process = safeGet(event, "process.name", null);
    const user = safeGet(event, "user.name", null);
    const technique = safeGet(event, "threat.technique.name", null);

    const nodes = [];
    const edges = [];
    const add = (id, label, category, size) => {
      if (id) {
        nodes.push(createNode(id, label, category, size));
      }
    };

    add(host, host, 0, 42);
    add(srcIp, srcIp, 1, 32);
    add(dstIp, dstIp, 1, 30);
    add(process, process, 2, 28);
    add(user, user, 3, 26);
    add(technique, technique, 4, 24);

    if (srcIp && host) {
      edges.push({ source: srcIp, target: host });
    }
    if (host && process) {
      edges.push({ source: host, target: process });
    }
    if (process && user) {
      edges.push({ source: process, target: user });
    }
    if (srcIp && dstIp) {
      edges.push({ source: srcIp, target: dstIp });
    }
    if (process && technique) {
      edges.push({ source: process, target: technique });
    }
    if (host && technique) {
      edges.push({ source: host, target: technique });
    }

    const primaryId = technique || process || host || srcIp || dstIp || user || null;

    return {
      index: index + 1,
      title: safeGet(event, "threat.technique.name", "可疑活动"),
      tactic: safeGet(event, "threat.tactic.name", "未知"),
      time: formatTime(event["@timestamp"]),
      path: `${safeGet(event, "source.ip", "-")} -> ${safeGet(event, "destination.ip", "-")}`,
      nodes,
      edges,
      primaryId,
    };
  };

  const buildSequence = (attacks) => {
    const maxSteps = 10;
    const ordered = [...attacks].sort((a, b) => parseTime(a) - parseTime(b)).slice(0, maxSteps);
    const fallbackEvents = [
      {
        "@timestamp": "2024-01-11T00:00:00Z",
        source: { ip: "203.0.113.5" },
        host: { name: "核心主机" },
        threat: { tactic: { name: "初始访问" }, technique: { name: "初始访问" } },
      },
      {
        "@timestamp": "2024-01-11T00:06:00Z",
        source: { ip: "203.0.113.5" },
        destination: { ip: "172.20.0.21" },
        host: { name: "核心主机" },
        process: { name: "SSH" },
        threat: { tactic: { name: "执行" }, technique: { name: "命令与脚本" } },
      },
      {
        "@timestamp": "2024-01-11T00:12:00Z",
        destination: { ip: "172.20.0.22" },
        host: { name: "内网跳板" },
        process: { name: "SSH" },
        threat: { tactic: { name: "横向移动" }, technique: { name: "横向移动" } },
      },
      {
        "@timestamp": "2024-01-11T00:20:00Z",
        host: { name: "内网跳板" },
        user: { name: "admin" },
        threat: { tactic: { name: "防御规避" }, technique: { name: "清理痕迹" } },
      },
    ];

    const base = ordered.length > 0 ? ordered : fallbackEvents;
    const steps = base.map((event, index) => buildStepFromEvent(event, index));

    steps.forEach((step, index) => {
      if (index === 0 || !step.primaryId) {
        return;
      }
      const prev = steps[index - 1];
      if (prev?.primaryId && prev.primaryId !== step.primaryId) {
        step.edges.push({ source: prev.primaryId, target: step.primaryId, trace: true });
      }
    });

    return steps;
  };

  const assembleGraph = (steps, uptoIndex) => {
    const nodeMap = new Map();
    const edgeMap = new Map();
    const end = Math.min(uptoIndex, steps.length - 1);

    for (let i = 0; i <= end; i += 1) {
      const step = steps[i];
      step.nodes.forEach((node) => {
        if (!nodeMap.has(node.id)) {
          nodeMap.set(node.id, { ...node });
        }
      });
      step.edges.forEach((edge) => {
        const key = `${edge.source}|${edge.target}`;
        if (!edgeMap.has(key)) {
          edgeMap.set(key, { ...edge });
        }
      });
    }

    const current = steps[end];
    if (current) {
      current.nodes.forEach((node) => {
        const existing = nodeMap.get(node.id);
        if (existing) {
          existing.itemStyle = {
            borderColor: "#ff7a18",
            borderWidth: 2.2,
            shadowBlur: 18,
            shadowColor: "rgba(255, 122, 24, 0.6)",
          };
          existing.symbolSize = (existing.symbolSize || 24) + 4;
        }
      });
      current.edges.forEach((edge) => {
        const key = `${edge.source}|${edge.target}`;
        const existing = edgeMap.get(key);
        if (existing) {
          existing.lineStyle = { color: "#ff7a18", width: 3.2 };
        }
      });
    }

    edgeMap.forEach((edge) => {
      if (edge.trace && !edge.lineStyle) {
        edge.lineStyle = { color: "#ff7a18", width: 2.6, type: "dashed" };
      }
    });

    return { nodes: [...nodeMap.values()], edges: [...edgeMap.values()] };
  };

  const renderGraph = (graph) => {
    if (!graphChart) {
      return;
    }
    const nodes = graph.nodes;
    const edges = graph.edges;
    graphChart.setOption({
      tooltip: {
        formatter: (params) => params.data.name,
        backgroundColor: "rgba(17, 24, 39, 0.85)",
        textStyle: { color: "#f7f1e6" },
      },
      legend: [
        {
          data: ["主机", "IP", "进程", "用户", "技法"],
          bottom: 0,
        },
      ],
      animationDurationUpdate: 1500,
      animationEasingUpdate: "cubicOut",
      series: [
        {
          type: "graph",
          layout: "force",
          data: nodes,
          links: edges,
          roam: true,
          label: { show: true, color: "#1d2433", fontSize: 11 },
          force: { repulsion: 140, edgeLength: 100 },
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: 8,
          categories: [
            { name: "主机", itemStyle: { color: "#00a6a6" } },
            { name: "IP", itemStyle: { color: "#ff7a18" } },
            { name: "进程", itemStyle: { color: "#2a3a55" } },
            { name: "用户", itemStyle: { color: "#f5b700" } },
            { name: "技法", itemStyle: { color: "#9fd4ff" } },
          ],
          lineStyle: { color: "rgba(17, 24, 39, 0.2)", width: 1.4 },
        },
      ],
    }, true);
  };

  const renderFlow = (attacks) => {
    if (!els.flowList) {
      return;
    }
    els.flowList.innerHTML = "";
    const ordered = [...attacks].sort((a, b) => parseTime(b) - parseTime(a)).slice(0, 8);
    ordered.forEach((event) => {
      const item = document.createElement("div");
      item.className = "list-item";
      const title = document.createElement("strong");
      const technique = safeGet(event, "threat.technique.name", "可疑活动");
      title.textContent = technique;
      const meta = document.createElement("span");
      const path = `${safeGet(event, "source.ip", "-")} -> ${safeGet(
        event,
        "destination.ip",
        "-"
      )}`;
      meta.textContent = `${path} | ${formatTime(event["@timestamp"])}`;
      item.appendChild(title);
      item.appendChild(meta);
      els.flowList.appendChild(item);
    });
  };

  const renderSequenceList = (steps) => {
    if (!els.sequenceList) {
      return;
    }
    els.sequenceList.innerHTML = "";
    steps.forEach((step) => {
      const item = document.createElement("div");
      item.className = "sequence-step";
      item.dataset.stepIndex = String(step.index);

      const node = document.createElement("div");
      node.className = "sequence-node";
      node.textContent = `#${step.index}`;

      const body = document.createElement("div");
      body.className = "sequence-body";

      const title = document.createElement("div");
      title.className = "sequence-title";
      title.textContent = step.title;

      const meta = document.createElement("div");
      meta.className = "sequence-meta";
      meta.textContent = `${step.tactic} · ${step.time}`;

      const pill = document.createElement("span");
      pill.className = "sequence-pill";
      pill.textContent = step.index === 1 ? "起点" : step.index === steps.length ? "终点" : "阶段";

      const path = document.createElement("div");
      path.className = "sequence-path mono";
      path.textContent = step.path;

      body.appendChild(pill);
      body.appendChild(title);
      body.appendChild(meta);
      body.appendChild(path);

      item.appendChild(node);
      item.appendChild(body);
      els.sequenceList.appendChild(item);
    });
  };

  const updateCounts = (graph) => {
    if (els.nodeCount) {
      els.nodeCount.textContent = formatNumber(graph.nodes.length);
    }
    if (els.edgeCount) {
      els.edgeCount.textContent = formatNumber(graph.edges.length);
    }
  };

  const setSequenceState = (activeIndex) => {
    if (!els.sequenceList) {
      return;
    }
    const items = Array.from(els.sequenceList.querySelectorAll(".sequence-step"));
    items.forEach((item, idx) => {
      item.classList.toggle("is-active", idx === activeIndex);
      item.classList.toggle("is-complete", idx < activeIndex);
    });
  };

  const updateControls = () => {
    if (!playBtn || !pauseBtn) {
      return;
    }
    playBtn.disabled = isPlaying;
    pauseBtn.disabled = !isPlaying;
  };

  const renderAtIndex = (index) => {
    if (!currentSteps.length) {
      return;
    }
    const graph = assembleGraph(currentSteps, index);
    renderGraph(graph);
    updateCounts(graph);
    setSequenceState(index);
  };

  const tick = () => {
    if (!currentSteps.length) {
      stopAnimation();
      return;
    }
    renderAtIndex(currentIndex);
    currentIndex += 1;
    if (currentIndex >= currentSteps.length) {
      stopAnimation();
      isPlaying = false;
      updateControls();
    }
  };

  const playSequence = (steps) => {
    if (!graphChart) {
      return;
    }
    stopAnimation();
    currentSteps = steps;
    currentIndex = 0;
    isPlaying = true;
    updateControls();
    tick();
    animationTimer = window.setInterval(tick, ANIMATION_INTERVAL);
  };

  const pauseSequence = () => {
    if (!isPlaying) {
      return;
    }
    stopAnimation();
    isPlaying = false;
    updateControls();
  };

  const resumeSequence = () => {
    if (isPlaying || !currentSteps.length) {
      return;
    }
    if (currentIndex >= currentSteps.length) {
      currentIndex = 0;
    }
    isPlaying = true;
    updateControls();
    tick();
    animationTimer = window.setInterval(tick, ANIMATION_INTERVAL);
  };

  const load = async () => {
    const hours = parseInt(els.range?.value || "24", 10);
    const attacksData = await fetchJson(`/api/attacks?hours=${hours}&limit=80`, sample.attacks);
    const attacks = attacksData.attacks || [];

    const steps = buildSequence(attacks);
    renderSequenceList(steps);
    playSequence(steps);
    renderFlow(attacks);
  };

  document.addEventListener("DOMContentLoaded", () => {
    initChart();
    load();
    if (els.rebuildBtn) {
      els.rebuildBtn.addEventListener("click", load);
    }
    if (els.range) {
      els.range.addEventListener("change", load);
    }
    playBtn = document.querySelector("#playBtn");
    pauseBtn = document.querySelector("#pauseBtn");
    if (playBtn) {
      playBtn.addEventListener("click", () => {
        resumeSequence();
      });
    }
    if (pauseBtn) {
      pauseBtn.addEventListener("click", () => {
        pauseSequence();
      });
    }
    window.addEventListener("resize", () => {
      if (graphChart) {
        graphChart.resize();
      }
    });
  });
})();
