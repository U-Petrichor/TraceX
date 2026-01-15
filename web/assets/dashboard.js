(() => {
  const { fetchJson, sample, formatNumber, formatTime, safeGet } = window.TraceX;

  const els = {
    totalEvents: document.querySelector("#totalEvents"),
    threatCount: document.querySelector("#threatCount"),
    threatRate: document.querySelector("#threatRate"),
    threatRatePulse: document.querySelector("#threatRatePulse"),
    periodLabel: document.querySelector("#periodLabel"),
    windowValue: document.querySelector("#windowValue"),
    signalList: document.querySelector("#signalList"),
    rangeSelect: document.querySelector("#rangeSelect"),
  };

  let trendChart;
  let tacticChart;

  const initCharts = () => {
    const trendEl = document.querySelector("#trendChart");
    const tacticEl = document.querySelector("#tacticChart");
    if (trendEl && window.echarts) {
      trendChart = window.echarts.init(trendEl);
    }
    if (tacticEl && window.echarts) {
      tacticChart = window.echarts.init(tacticEl);
    }
  };

  const updateStats = (stats) => {
    const total = stats?.total_events ?? 0;
    const threats = stats?.threat_count ?? 0;
    const ratio = total > 0 ? ((threats / total) * 100).toFixed(2) : "0.0"; // Increased precision to 2 decimal places

    if (els.totalEvents) {
      els.totalEvents.textContent = formatNumber(total);
    }
    if (els.threatCount) {
      els.threatCount.textContent = formatNumber(threats);
    }
    if (els.threatRate) {
      els.threatRate.textContent = `${ratio}%`;
    }
    if (els.threatRatePulse) {
      els.threatRatePulse.textContent = `${ratio}%`;
    }
    if (els.periodLabel) {
      els.periodLabel.textContent = `最近 ${stats?.period_hours ?? 24} 小时`;
    }
    if (els.windowValue) {
      els.windowValue.textContent = `${stats?.period_hours ?? 24} 小时`;
    }
  };

  const updateTrend = (data) => {
    if (!trendChart) {
      return;
    }
    const times = data.map((item) => item.time.slice(11, 16));
    const values = data.map((item) => item.count);

    trendChart.setOption({
      grid: { left: 10, right: 12, top: 30, bottom: 20, containLabel: true },
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
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(17, 24, 39, 0.85)",
        textStyle: { color: "#f7f1e6" },
      },
      series: [
        {
          type: "line",
          smooth: true,
          data: values,
          lineStyle: { color: "#ff7a18", width: 3 },
          areaStyle: {
            color: new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "rgba(255, 122, 24, 0.35)" },
              { offset: 1, color: "rgba(255, 122, 24, 0.02)" },
            ]),
          },
          symbol: "circle",
          symbolSize: 6,
        },
      ],
    });
  };

  const updateTactics = (attacks) => {
    if (!tacticChart) {
      return;
    }
    const bucket = {};
    attacks.forEach((event) => {
      const tactic = safeGet(event, "threat.tactic.name", "未知");
      bucket[tactic] = (bucket[tactic] || 0) + 1;
    });

    const labels = Object.keys(bucket).slice(0, 6);
    const values = labels.map((label) => bucket[label]);

    tacticChart.setOption({
      grid: { left: 10, right: 10, top: 20, bottom: 10, containLabel: true },
      xAxis: {
        type: "value",
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: "rgba(17, 24, 39, 0.08)" } },
        axisLabel: { color: "#596275", fontSize: 11 },
      },
      yAxis: {
        type: "category",
        data: labels,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: "#596275", fontSize: 12 },
      },
      series: [
        {
          type: "bar",
          data: values,
          barWidth: 14,
          itemStyle: {
            borderRadius: [10, 10, 10, 10],
            color: new window.echarts.graphic.LinearGradient(1, 0, 0, 0, [
              { offset: 0, color: "#00a6a6" },
              { offset: 1, color: "#9fd4ff" },
            ]),
          },
        },
      ],
    });
  };

  const updateSignals = (logs) => {
    if (!els.signalList) {
      return;
    }
    els.signalList.innerHTML = "";
    if (!logs.length) {
      const empty = document.createElement("div");
      empty.className = "list-item";
      empty.textContent = "暂无可用信号";
      els.signalList.appendChild(empty);
      return;
    }
    logs.forEach((log) => {
      const item = document.createElement("div");
      item.className = "list-item";
      const title = document.createElement("strong");
      const message = log.message || safeGet(log, "event.original", "信号");
      title.textContent = message;
      const meta = document.createElement("span");
      const dataset = safeGet(log, "event.dataset", "未知");
      const timestamp = formatTime(log["@timestamp"]);
      meta.textContent = `${dataset} | ${timestamp}`;
      item.appendChild(title);
      item.appendChild(meta);
      els.signalList.appendChild(item);
    });
  };

  const load = async () => {
    const hours = parseInt(els.rangeSelect?.value || "24", 10);
    const stats = await fetchJson(`/api/stats?hours=${hours}`);
    const trend = await fetchJson(`/api/trend?hours=${hours}&interval=1h`);
    const attacks = await fetchJson(`/api/attacks?hours=${hours}&limit=60`);
    const logs = await fetchJson(`/api/logs?page=1&size=6`);

    const statsPayload =
      stats && !stats.error ? stats : { total_events: 0, threat_count: 0, period_hours: hours };
    const trendPayload = trend && !trend.error ? trend.data || [] : [];
    const attacksPayload = attacks && !attacks.error ? attacks.attacks || [] : [];
    const logsPayload = logs && !logs.error ? logs.data || [] : [];

    updateStats(statsPayload);
    updateTrend(trendPayload);
    updateTactics(attacksPayload);
    updateSignals(logsPayload);
  };

  document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    load();
    if (els.rangeSelect) {
      els.rangeSelect.addEventListener("change", load);
    }
    window.addEventListener("resize", () => {
      if (trendChart) {
        trendChart.resize();
      }
      if (tacticChart) {
        tacticChart.resize();
      }
    });
  });
})();
