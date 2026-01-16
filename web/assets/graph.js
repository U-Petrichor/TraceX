(() => {
  const { fetchJson, formatNumber } = window.TraceX;

  const els = {
    data: document.querySelector("#dataSelect"),
    mode: document.querySelector("#modeSelect"),
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

  const TYPE_CATEGORY = {
    host: 0,
    network: 1,
    process: 2,
    user: 3,
    file: 4,
    technique: 5,
  };

  const CATEGORY_CONFIG = [
    { name: "主机", itemStyle: { color: "#00a6a6" } },
    { name: "网络", itemStyle: { color: "#ff7a18" } },
    { name: "进程", itemStyle: { color: "#2a3a55" } },
    { name: "用户", itemStyle: { color: "#f5b700" } },
    { name: "文件", itemStyle: { color: "#9fd4ff" } },
    { name: "技术", itemStyle: { color: "#e11d48" } }, // TNode (Technique)
    { name: "未知", itemStyle: { color: "#9aa3b2" } },
  ];

  const SIZE_MAP = {
    host: 44,
    network: 36,
    process: 32,
    user: 30,
    file: 28,
    technique: 40,
    unknown: 28,
  };

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

  const normalizeType = (value) => {
    const raw = String(value || "unknown").toLowerCase();
    if (raw === "ip" || raw === "net" || raw === "network") {
      return "network";
    }
    if (raw === "proc" || raw === "process") {
      return "process";
    }
    if (raw === "usr" || raw === "user") {
      return "user";
    }
    if (raw === "file") {
      return "file";
    }
    if (raw === "host" || raw === "endpoint") {
      return "host";
    }
    if (raw === "tnode" || raw === "technique" || raw === "tactic") {
      return "technique";
    }
    return "unknown";
  };

  const shortenLabel = (label, type) => {
    const raw = label || "-";
    if (type === "file" || type === "process") {
      const parts = raw.split(/[/\\]/);
      return parts[parts.length - 1] || raw;
    }
    if (type === "network") {
      return raw.replace(/^https?:/i, "");
    }
    if (raw.length <= 22) {
      return raw;
    }
    return `${raw.slice(0, 10)}…${raw.slice(-8)}`;
  };

  const createNode = (id, label, type) => ({
    id,
    name: label || "-",
    displayName: shortenLabel(label || "-", type),
    category: TYPE_CATEGORY[type] ?? 5,
    symbolSize: SIZE_MAP[type] || SIZE_MAP.unknown,
  });

  const parseChainItem = (item) => {
    if (!item) {
      return null;
    }
    if (typeof item === "string") {
      const match = item.match(/\[(.+?)\]\s+(.+?)\s+--(.+?)-->\s+\[(.+?)\]\s+(.+)/);
      if (!match) {
        return null;
      }
      return {
        sourceType: normalizeType(match[1]),
        sourceLabel: match[2].trim(),
        relation: match[3].trim(),
        targetType: normalizeType(match[4]),
        targetLabel: match[5].trim(),
      };
    }
    const source = item.source || item.from || item.src || item.source_label;
    const target = item.target || item.to || item.dst || item.target_label;
    const sourceLabel = typeof source === "string" ? source : source?.label || source?.name || source?.id;
    const targetLabel = typeof target === "string" ? target : target?.label || target?.name || target?.id;
    if (!sourceLabel || !targetLabel) {
      return null;
    }
    return {
      sourceType: normalizeType(item.source_type || item.sourceType || source?.type),
      sourceLabel: sourceLabel,
      relation: item.relation || item.edge || item.link || "related",
      targetType: normalizeType(item.target_type || item.targetType || target?.type),
      targetLabel: targetLabel,
    };
  };

  const normalizeChain = (rawChain) => {
    const list = Array.isArray(rawChain) ? rawChain : [];
    // [FIX] 移除了基于 label 的去重逻辑，保留所有边（按时间顺序）
    // 不同进程实例现在通过 PID 在 label 中区分
    return list.map((item) => parseChainItem(item)).filter(Boolean);
  };

  const buildGraph = (chain) => {
    const nodeMap = new Map();
    const edgeMap = new Map();
    chain.forEach((edge) => {
      const sourceId = `${edge.sourceType}:${edge.sourceLabel}`;
      const targetId = `${edge.targetType}:${edge.targetLabel}`;
      if (!nodeMap.has(sourceId)) {
        nodeMap.set(sourceId, createNode(sourceId, edge.sourceLabel, edge.sourceType));
      }
      if (!nodeMap.has(targetId)) {
        nodeMap.set(targetId, createNode(targetId, edge.targetLabel, edge.targetType));
      }
      const key = `${sourceId}|${edge.relation}|${targetId}`;
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { source: sourceId, target: targetId, relation: edge.relation });
      }
    });
    return { nodes: [...nodeMap.values()], edges: [...edgeMap.values()] };
  };

  const buildStepsFromChain = (chain) => {
    const steps = chain.map((edge, index) => {
      const sourceId = `${edge.sourceType}:${edge.sourceLabel}`;
      const targetId = `${edge.targetType}:${edge.targetLabel}`;
      const nodes = [
        createNode(sourceId, edge.sourceLabel, edge.sourceType),
        createNode(targetId, edge.targetLabel, edge.targetType),
      ];
      const edges = [{ source: sourceId, target: targetId }];
      return {
        index: index + 1,
        title: `${shortenLabel(edge.sourceLabel, edge.sourceType)} → ${shortenLabel(
          edge.targetLabel,
          edge.targetType
        )}`,
        tactic: edge.relation || "路径",
        time: `步骤 ${index + 1}`,
        path: `${shortenLabel(edge.sourceLabel, edge.sourceType)} -> ${shortenLabel(
          edge.targetLabel,
          edge.targetType
        )}`,
        nodes,
        edges,
        primaryId: targetId,
      };
    });

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
    graphChart.setOption(
      {
        tooltip: {
          formatter: (params) => {
            if (params.data?.relation) {
              return `${params.data.relation}<br/>${params.data.source} → ${params.data.target}`;
            }
            return params.data.name;
          },
          backgroundColor: "rgba(17, 24, 39, 0.85)",
          textStyle: { color: "#f7f1e6" },
        },
        legend: [
          {
            data: CATEGORY_CONFIG.map((item) => item.name),
            bottom: 0,
          },
        ],
        animationDurationUpdate: 1500,
        animationEasingUpdate: "cubicOut",
        series: [
          {
            type: "graph",
            layout: "force",
            data: graph.nodes,
            links: graph.edges,
            roam: true,
            label: {
              show: true,
              color: "#1d2433",
              fontSize: 11,
              backgroundColor: "rgba(255, 255, 255, 0.75)",
              padding: [2, 6],
              borderRadius: 6,
              width: 120,
              overflow: "truncate",
              formatter: (params) => params.data.displayName || params.data.name,
            },
            labelLayout: { hideOverlap: true },
            force: { repulsion: 220, edgeLength: [120, 200], gravity: 0.08 },
            edgeSymbol: ["none", "arrow"],
            edgeSymbolSize: 6,
            categories: CATEGORY_CONFIG,
            lineStyle: { color: "rgba(17, 24, 39, 0.16)", width: 1.2, curveness: 0.18 },
            emphasis: {
              focus: "adjacency",
              lineStyle: { color: "#ff7a18", width: 2.6 },
            },
          },
        ],
      },
      true
    );
  };

  const renderFlow = (chain) => {
    if (!els.flowList) {
      return;
    }
    els.flowList.innerHTML = "";
    if (!chain.length) {
      const empty = document.createElement("div");
      empty.className = "list-item";
      empty.textContent = "暂无路径数据";
      els.flowList.appendChild(empty);
      return;
    }
    chain.slice(0, 8).forEach((edge) => {
      const item = document.createElement("div");
      item.className = "list-item";
      const title = document.createElement("strong");
      title.textContent = `${shortenLabel(edge.sourceLabel, edge.sourceType)} → ${shortenLabel(
        edge.targetLabel,
        edge.targetType
      )}`;
      const meta = document.createElement("span");
      meta.textContent = `[${edge.sourceType}] ${edge.relation} → [${edge.targetType}]`;
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
    if (!steps.length) {
      const empty = document.createElement("div");
      empty.className = "inline-note";
      empty.textContent = "暂无攻击链序列";
      els.sequenceList.appendChild(empty);
      return;
    }
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

  const buildRequestUrl = (refresh) => {
    const data = els.data?.value || "APT28.jsonl";
    // const mode = els.mode?.value || "direct"; // Removed mode selection
    const mode = "direct";
    const refreshFlag = refresh ? "&refresh=1" : "";
    return `/api/apt-report?mode=${encodeURIComponent(mode)}&data=${encodeURIComponent(data)}${refreshFlag}`;
  };

  const load = async (refresh = false) => {
    const report = await fetchJson(buildRequestUrl(refresh));
    if (report?.error) {
      renderFlow([]);
      renderSequenceList([]);
      renderGraph({ nodes: [], edges: [] });
      updateCounts({ nodes: [], edges: [] });
      return;
    }
    const payload = report?.report || report || {};
    const chain = normalizeChain(payload.attack_chain_structure);
    const graph = buildGraph(chain);
    const steps = buildStepsFromChain(chain);

    renderSequenceList(steps);
    renderFlow(chain);
    if (steps.length) {
      playSequence(steps);
    } else {
      renderGraph(graph);
      updateCounts(graph);
    }
  };

  document.addEventListener("DOMContentLoaded", () => {
    initChart();
    load();
    if (els.rebuildBtn) {
      els.rebuildBtn.addEventListener("click", () => load(true));
    }
    if (els.data) {
      els.data.addEventListener("change", () => load(true));
    }
    if (els.mode) {
      els.mode.addEventListener("change", () => load(true));
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
