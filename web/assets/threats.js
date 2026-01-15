(() => {
  const { fetchJson, sample, safeGet, formatTime, formatNumber } = window.TraceX;

  const els = {
    range: document.querySelector("#rangeSelect"),
    limit: document.querySelector("#limitSelect"),
    attackCount: document.querySelector("#attackCount"),
    highCount: document.querySelector("#highCount"),
    topTactic: document.querySelector("#topTactic"),
    threatGrid: document.querySelector("#threatGrid"),
  };

  let severityChart;
  let tacticChart;
  let timelineChart;

  const severityLabel = (value) => {
    const key = (value || "").toLowerCase();
    if (key === "high") {
      return "高危";
    }
    if (key === "medium") {
      return "中危";
    }
    if (key === "low") {
      return "低危";
    }
    return "未知";
  };

  const initCharts = () => {
    const severityEl = document.querySelector("#severityChart");
    const tacticEl = document.querySelector("#tacticPie");
    const timelineEl = document.querySelector("#timelineChart");

    if (severityEl && window.echarts) {
      severityChart = window.echarts.init(severityEl);
    }
    if (tacticEl && window.echarts) {
      tacticChart = window.echarts.init(tacticEl);
    }
    if (timelineEl && window.echarts) {
      timelineChart = window.echarts.init(timelineEl);
    }
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

    if (els.attackCount) {
      els.attackCount.textContent = formatNumber(total);
    }
    if (els.highCount) {
      els.highCount.textContent = formatNumber(high);
    }
    if (els.topTactic) {
      els.topTactic.textContent = top ? top[0] : "未知";
    }
  };

  const updateSeverity = (attacks) => {
    if (!severityChart) {
      return;
    }
    const bucket = { high: 0, medium: 0, low: 0, unknown: 0 };
    attacks.forEach((item) => {
      const level = safeGet(item, "detection.severity", "unknown").toLowerCase();
      if (bucket[level] == null) {
        bucket.unknown += 1;
      } else {
        bucket[level] += 1;
      }
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
    if (!tacticChart) {
      return;
    }
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
    if (!timelineChart) {
      return;
    }
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

  const renderThreats = (attacks) => {
    if (!els.threatGrid) {
      return;
    }
    els.threatGrid.innerHTML = "";
    const score = (item) => {
      const confidence = Number(safeGet(item, "threat.confidence", 0));
      const severity = safeGet(item, "detection.severity", "").toLowerCase();
      const severityWeight = severity === "high" ? 1 : severity === "medium" ? 0.6 : severity === "low" ? 0.3 : 0.2;
      return confidence * 100 + severityWeight * 40;
    };
    const sorted = [...attacks].sort((a, b) => score(b) - score(a));
    sorted.forEach((attack) => {
      const card = document.createElement("div");
      card.className = "card";

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

      const meta = document.createElement("div");
      meta.className = "card-sub";
      const host = safeGet(attack, "host.name", "未知主机");
      const src = safeGet(attack, "source.ip", "-");
      const dst = safeGet(attack, "destination.ip", "-");
      meta.textContent = `${host} | ${src} -> ${dst}`;

      const badges = document.createElement("div");
      badges.className = "input-group";
      const severity = severityLabel(safeGet(attack, "detection.severity", "unknown"));
      const dataset = safeGet(attack, "event.dataset", "未知");
      const tactic = safeGet(attack, "threat.tactic.name", "未知");
      [severity, dataset, tactic].forEach((label) => {
        const pill = document.createElement("span");
        pill.className = "badge";
        pill.textContent = label;
        badges.appendChild(pill);
      });

      const time = document.createElement("div");
      time.className = "inline-note";
      time.textContent = formatTime(attack["@timestamp"]);

      card.appendChild(header);
      card.appendChild(meta);
      card.appendChild(badges);
      card.appendChild(time);
      els.threatGrid.appendChild(card);
    });
  };

  const load = async () => {
    const hours = parseInt(els.range?.value || "24", 10);
    const limit = parseInt(els.limit?.value || "60", 10);

    const attacksData = await fetchJson(`/api/attacks?hours=${hours}&limit=${limit}`, sample.attacks);
    const trendData = await fetchJson(`/api/trend?hours=${hours}&interval=2h`, sample.trend);

    const attacks = attacksData.attacks || [];

    updateSummary(attacks);
    updateSeverity(attacks);
    updateTactics(attacks);
    updateTimeline(trendData.data || []);
    renderThreats(attacks);
  };

  document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    load();
    if (els.range) {
      els.range.addEventListener("change", load);
    }
    if (els.limit) {
      els.limit.addEventListener("change", load);
    }
    window.addEventListener("resize", () => {
      if (severityChart) {
        severityChart.resize();
      }
      if (tacticChart) {
        tacticChart.resize();
      }
      if (timelineChart) {
        timelineChart.resize();
      }
    });
  });
})();
