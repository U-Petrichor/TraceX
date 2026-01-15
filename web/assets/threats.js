(() => {
  const { fetchJson, sample, safeGet, formatTime, formatNumber } = window.TraceX;

  const els = {
    range: document.querySelector("#rangeSelect"),
    limit: document.querySelector("#limitSelect"),
    attackCount: document.querySelector("#attackCount"),
    highCount: document.querySelector("#highCount"),
    topTactic: document.querySelector("#topTactic"),
    threatGrid: document.querySelector("#threatGrid"),
    // Modal Elements
    modal: document.querySelector("#detailModal"),
    modalClose: document.querySelector("#modalClose"),
    modalTitle: document.querySelector("#modalTitle"),
    modalBasicInfo: document.querySelector("#modalBasicInfo"),
    nodozeGauge: document.querySelector("#nodozeGauge"),
    nodozeScoreVal: document.querySelector("#nodozeScoreVal"),
    atlasChain: document.querySelector("#atlasChain"),
  };

  let severityChart;
  let tacticChart;
  let timelineChart;
  let nodozeChart;

  const severityLabel = (value) => {
    const key = (value || "").toLowerCase();
    if (key === "high") return "高危";
    if (key === "medium") return "中危";
    if (key === "low") return "低危";
    return "未知";
  };

  const initCharts = () => {
    const severityEl = document.querySelector("#severityChart");
    const tacticEl = document.querySelector("#tacticPie");
    const timelineEl = document.querySelector("#timelineChart");

    if (severityEl && window.echarts) severityChart = window.echarts.init(severityEl);
    if (tacticEl && window.echarts) tacticChart = window.echarts.init(tacticEl);
    if (timelineEl && window.echarts) timelineChart = window.echarts.init(timelineEl);
  };

  const updateSummary = (attacks) => {
    const total = attacks.length;
    const high = attacks.filter((item) => safeGet(item, "detection.severity", "").toLowerCase() === "high").length;
    const tacticBucket = {};
    attacks.forEach((item) => {
      const tactic = safeGet(item, "threat.tactic.name", "未知");
      tacticBucket[tactic] = (tacticBucket[tactic] || 0) + 1;
    });
    const top = Object.entries(tacticBucket).sort((a, b) => b[1] - a[1])[0];

    if (els.attackCount) els.attackCount.textContent = formatNumber(total);
    if (els.highCount) els.highCount.textContent = formatNumber(high);
    if (els.topTactic) els.topTactic.textContent = top ? top[0] : "未知";
  };

  const updateSeverity = (attacks) => {
    if (!severityChart) return;
    const bucket = { high: 0, medium: 0, low: 0, unknown: 0 };
    attacks.forEach((item) => {
      const level = safeGet(item, "detection.severity", "unknown").toLowerCase();
      if (bucket[level] == null) bucket.unknown += 1;
      else bucket[level] += 1;
    });

    severityChart.setOption({
      xAxis: {
        type: "category",
        data: ["高危", "中危", "低危", "未知"],
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: "#596275" },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: "rgba(17, 24, 39, 0.08)" } },
        axisLabel: { color: "#596275" },
      },
      series: [
        {
          type: "bar",
          data: [bucket.high, bucket.medium, bucket.low, bucket.unknown],
          barWidth: 20,
          itemStyle: {
            borderRadius: [10, 10, 0, 0],
            color: new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "#ff7a18" },
              { offset: 1, color: "#f5b700" },
            ]),
          },
        },
      ],
    });
  };

  const updateTactics = (attacks) => {
    if (!tacticChart) return;
    const bucket = {};
    attacks.forEach((item) => {
      const tactic = safeGet(item, "threat.tactic.name", "未知");
      bucket[tactic] = (bucket[tactic] || 0) + 1;
    });
    const data = Object.entries(bucket).map(([name, value]) => ({ name, value }));

    tacticChart.setOption({
      tooltip: { trigger: "item" },
      series: [
        {
          type: "pie",
          radius: ["45%", "70%"],
          data,
          label: { color: "#1d2433" },
          itemStyle: {
            borderColor: "#ffffff",
            borderWidth: 2,
          },
        },
      ],
    });
  };

  const updateTimeline = (trend) => {
    if (!timelineChart) return;
    const times = trend.map((item) => item.time.slice(11, 16));
    const values = trend.map((item) => item.count);
    timelineChart.setOption({
      grid: { left: 10, right: 10, top: 20, bottom: 20, containLabel: true },
      xAxis: {
        type: "category",
        data: times,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: "#596275", fontSize: 11 },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: "rgba(17, 24, 39, 0.08)" } },
        axisLabel: { color: "#596275", fontSize: 11 },
      },
      series: [
        {
          type: "line",
          smooth: true,
          data: values,
          lineStyle: { color: "#00a6a6", width: 2 },
          areaStyle: {
            color: new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "rgba(0, 166, 166, 0.35)" },
              { offset: 1, color: "rgba(0, 166, 166, 0.05)" },
            ]),
          },
          symbol: "circle",
          symbolSize: 5,
        },
      ],
    });
  };

  // --- Modal & Detail View Logic ---

  const renderNoDozeGauge = (score) => {
    if (!els.nodozeGauge) return;
    if (!nodozeChart) {
      nodozeChart = window.echarts.init(els.nodozeGauge);
    }
    
    const color = score > 80 ? '#ff7a18' : score > 50 ? '#f5b700' : '#00a6a6';
    
    nodozeChart.setOption({
      series: [
        {
          type: 'gauge',
          startAngle: 90,
          endAngle: -270,
          min: 0,
          max: 100,
          radius: '80%',
          center: ['50%', '50%'],
          itemStyle: {
            color: color,
            shadowColor: 'rgba(0,0,0,0.1)',
            shadowBlur: 10
          },
          progress: {
            show: true,
            roundCap: true,
            width: 18
          },
          pointer: {
            show: false
          },
          axisLine: {
            roundCap: true,
            lineStyle: {
              width: 18,
              color: [[1, 'rgba(0,0,0,0.06)']]
            }
          },
          axisTick: {
            show: false
          },
          splitLine: {
            show: false
          },
          axisLabel: {
            show: false
          },
          title: {
            show: false
          },
          detail: {
            valueAnimation: true,
            offsetCenter: [0, 0],
            formatter: function (value) {
              return '{value|' + Math.round(value) + '}\n{unit|分}';
            },
            rich: {
              value: {
                fontSize: 48,
                fontWeight: '700',
                color: '#1d2433',
                fontFamily: 'Space Grotesk, sans-serif'
              },
              unit: {
                fontSize: 14,
                color: '#999',
                padding: [10, 0, 0, 0]
              }
            }
          },
          data: [
            {
              value: score
            }
          ]
        }
      ]
    });
    
    // Hide the external text since it's now inside the gauge
    if(els.nodozeScoreVal) {
        els.nodozeScoreVal.style.display = 'none';
    }
  };

  const renderAtlasChain = (chain) => {
    if (!els.atlasChain) return;
    els.atlasChain.innerHTML = "";
    
    if (!chain || chain.length === 0) {
      els.atlasChain.innerHTML = "<div style='color:#999'>暂无攻击链数据</div>";
      return;
    }
    
    chain.forEach((step, index) => {
      const isCurrent = step.is_current;
      const el = document.createElement("div");
      el.className = `atlas-step ${isCurrent ? 'current' : ''}`;
      el.style.animationDelay = `${index * 100}ms`;
      
      el.innerHTML = `
        <div class="atlas-phase">${step.phase || 'Unknown Phase'}</div>
        <div class="atlas-action">${step.action || step.technique || 'Unknown Action'}</div>
        <div class="atlas-time">
            <span>${formatTime(step.timestamp)}</span>
            <span>Score: ${step.score || '-'}</span>
        </div>
      `;
      els.atlasChain.appendChild(el);
    });
  };

  const openDetail = (attack) => {
    // 1. Fill Basic Info
    const kvData = [
      { k: "技术 (Technique)", v: safeGet(attack, "threat.technique.name", "N/A") },
      { k: "战术 (Tactic)", v: safeGet(attack, "threat.tactic.name", "N/A") },
      { k: "置信度", v: `${Math.round(Number(safeGet(attack, "threat.confidence", 0)) * 100)}%` },
      { k: "主机", v: safeGet(attack, "host.name", "N/A") },
      { k: "源 IP", v: safeGet(attack, "source.ip", "-") },
      { k: "目标 IP", v: safeGet(attack, "destination.ip", "-") },
      { k: "时间", v: formatTime(attack["@timestamp"]) }
    ];
    
    if(els.modalBasicInfo) {
        els.modalBasicInfo.innerHTML = kvData.map(item => `
            <div class="kv-item">
                <span class="kv-key">${item.k}</span>
                <span class="kv-val">${item.v}</span>
            </div>
        `).join('');
    }
    
    if(els.modalTitle) {
        els.modalTitle.textContent = `威胁详情: ${safeGet(attack, "threat.technique.name", "未知威胁")}`;
    }

    // 2. Render NoDoze
    const nodozeScore = attack.nodoze_score || 0;
    renderNoDozeGauge(nodozeScore);

    // 3. Render ATLAS
    const chain = attack.atlas_chain || [];
    renderAtlasChain(chain);

    // 4. Show Modal
    if(els.modal) {
        els.modal.hidden = false;
        els.modal.classList.add('active');
    }
  };

  const closeDetail = () => {
    if(els.modal) {
        els.modal.hidden = true;
        els.modal.classList.remove('active');
    }
  };

  const renderThreats = (attacks) => {
    if (!els.threatGrid) return;
    els.threatGrid.innerHTML = "";
    
    if (!attacks.length) {
      const empty = document.createElement("div");
      empty.className = "card";
      empty.textContent = "暂无威胁信号";
      els.threatGrid.appendChild(empty);
      return;
    }
    
    const score = (item) => {
      const confidence = Number(safeGet(item, "threat.confidence", 0));
      const severity = safeGet(item, "detection.severity", "").toLowerCase();
      const severityWeight = severity === "high" ? 1 : severity === "medium" ? 0.6 : severity === "low" ? 0.3 : 0.2;
      return confidence * 100 + severityWeight * 40;
    };
    
    const sorted = [...attacks].sort((a, b) => score(b) - score(a));
    
    sorted.forEach((attack, index) => {
      const card = document.createElement("div");
      card.className = "card";
      card.style.cursor = "pointer"; // Make it look clickable
      card.dataset.delay = (index % 3) + 1; // Stagger animation

      // --- Header ---
      const header = document.createElement("div");
      header.className = "card-header";

      const title = document.createElement("div");
      title.className = "card-title";
      title.textContent = safeGet(attack, "threat.technique.name", "可疑活动");

      const confidence = Number(safeGet(attack, "threat.confidence", 0)) * 100;
      const scoreBadge = document.createElement("span");
      scoreBadge.className = "badge";
      scoreBadge.textContent = `评分 ${Math.round(confidence)}`;

      header.appendChild(title);
      header.appendChild(scoreBadge);

      // --- Meta ---
      const meta = document.createElement("div");
      meta.className = "card-sub";
      const host = safeGet(attack, "host.name", "未知主机");
      const src = safeGet(attack, "source.ip", "-");
      const dst = safeGet(attack, "destination.ip", "-");
      meta.textContent = `${host} | ${src} -> ${dst}`;

      // --- Badges ---
      const badges = document.createElement("div");
      badges.className = "input-group";
      badges.style.marginTop = "12px";
      
      const severity = severityLabel(safeGet(attack, "detection.severity", "unknown"));
      const dataset = safeGet(attack, "event.dataset", "未知");
      const tactic = safeGet(attack, "threat.tactic.name", "未知");
      
      // New: Frequency Badge (NoDoze)
      const freqScore = attack.nodoze_score || 0;
      const freqLabel = freqScore > 80 ? "极罕见" : freqScore > 50 ? "罕见" : "常见";
      const freqColor = freqScore > 80 ? "danger" : freqScore > 50 ? "warn" : "safe";
      
      [
          {text: severity, cls: "badge"},
          {text: dataset, cls: "badge"},
          {text: tactic, cls: "badge"},
          {text: `Freq: ${freqScore}`, cls: `badge ${freqColor}`} // Add Freq Badge
      ].forEach((item) => {
        const pill = document.createElement("span");
        pill.className = item.cls;
        pill.textContent = item.text;
        badges.appendChild(pill);
      });

      // --- Footer ---
      const time = document.createElement("div");
      time.className = "inline-note";
      time.style.marginTop = "12px";
      time.textContent = formatTime(attack["@timestamp"]);

      card.appendChild(header);
      card.appendChild(meta);
      card.appendChild(badges);
      card.appendChild(time);
      
      // Click Event
      card.addEventListener("click", () => openDetail(attack));
      
      els.threatGrid.appendChild(card);
    });
  };

  const load = async () => {
    const hours = parseInt(els.range?.value || "24", 10);
    const limit = parseInt(els.limit?.value || "60", 10);

    const attacksData = await fetchJson(`/api/attacks?hours=${hours}&limit=${limit}`);
    const trendData = await fetchJson(`/api/trend?hours=${hours}&interval=2h`);

    const attacks = attacksData && !attacksData.error ? attacksData.attacks || [] : [];
    const trend = trendData && !trendData.error ? trendData.data || [] : [];

    updateSummary(attacks);
    updateSeverity(attacks);
    updateTactics(attacks);
    updateTimeline(trend);
    renderThreats(attacks);
  };

  document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    load();
    if (els.range) els.range.addEventListener("change", load);
    if (els.limit) els.limit.addEventListener("change", load);
    
    // Modal Close Events
    if (els.modalClose) els.modalClose.addEventListener("click", closeDetail);
    if (els.modal) {
        els.modal.addEventListener("click", (e) => {
            if(e.target === els.modal) closeDetail();
        });
    }
    
    window.addEventListener("resize", () => {
      if (severityChart) severityChart.resize();
      if (tacticChart) tacticChart.resize();
      if (timelineChart) timelineChart.resize();
      if (nodozeChart) nodozeChart.resize();
    });
  });
})();
