(() => {
  const { fetchJson, sample, safeGet, formatTime, formatNumber } = window.TraceX;

  const els = {
    searchInput: document.querySelector("#searchInput"),
    searchBtn: document.querySelector("#searchBtn"),
    tableBody: document.querySelector("#logTableBody"),
    totalLabel: document.querySelector("#totalLabel"),
    pageLabel: document.querySelector("#pageLabel"),
    prevBtn: document.querySelector("#prevPage"),
    nextBtn: document.querySelector("#nextPage"),
    detailsPre: document.querySelector("#logDetails"),
    detailsMeta: document.querySelector("#detailMeta"),
  };

  const state = {
    page: 1,
    size: 16,
    query: "",
  };

  const renderRows = (logs) => {
    if (!els.tableBody) {
      return;
    }
    els.tableBody.innerHTML = "";
    logs.forEach((log) => {
      const row = document.createElement("tr");
      const time = document.createElement("td");
      time.textContent = formatTime(log["@timestamp"]);

      const dataset = document.createElement("td");
      dataset.textContent = safeGet(log, "event.dataset", "-");

      const message = document.createElement("td");
      const messageValue =
        log.message ||
        safeGet(log, "event.original", "") ||
        safeGet(log, "process.command_line", "") ||
        safeGet(log, "raw.data", "") ||
        "-";
      message.textContent = messageValue;

      const host = document.createElement("td");
      host.textContent = safeGet(log, "host.name", "-");

      const source = document.createElement("td");
      source.textContent = safeGet(log, "source.ip", "-");

      row.appendChild(time);
      row.appendChild(dataset);
      row.appendChild(message);
      row.appendChild(host);
      row.appendChild(source);

      row.addEventListener("click", () => {
        if (els.detailsPre) {
          els.detailsPre.textContent = JSON.stringify(log, null, 2);
        }
        if (els.detailsMeta) {
          const summary = `${safeGet(log, "event.dataset", "-")} | ${formatTime(log["@timestamp"])}`;
          els.detailsMeta.textContent = summary;
        }
      });

      els.tableBody.appendChild(row);
    });
  };

  const updatePagination = (total) => {
    const totalPages = Math.max(1, Math.ceil(total / state.size));
    if (els.pageLabel) {
      els.pageLabel.textContent = `第 ${state.page} / ${totalPages} 页`;
    }
    if (els.prevBtn) {
      els.prevBtn.disabled = state.page <= 1;
    }
    if (els.nextBtn) {
      els.nextBtn.disabled = state.page >= totalPages;
    }
  };

  const load = async () => {
    const queryPart = state.query ? `&query=${encodeURIComponent(state.query)}` : "";
    const data = await fetchJson(`/api/logs?page=${state.page}&size=${state.size}${queryPart}`);
    const logs = data && !data.error ? data.data || [] : [];
    const total = data && !data.error ? data.total || 0 : 0;

    if (els.totalLabel) {
      els.totalLabel.textContent = `总计 ${formatNumber(total)}`;
    }
    renderRows(logs);
    updatePagination(total);

    if (els.detailsPre && !els.detailsPre.textContent && logs && logs[0]) {
      els.detailsPre.textContent = JSON.stringify(logs[0], null, 2);
      if (els.detailsMeta) {
        els.detailsMeta.textContent = `${safeGet(logs[0], "event.dataset", "-")} | ${formatTime(
          logs[0]["@timestamp"]
        )}`;
      }
    }
  };

  const search = () => {
    state.query = els.searchInput?.value.trim() || "";
    state.page = 1;
    load();
  };

  document.addEventListener("DOMContentLoaded", () => {
    load();

    if (els.searchBtn) {
      els.searchBtn.addEventListener("click", search);
    }
    if (els.searchInput) {
      els.searchInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          search();
        }
      });
    }
    if (els.prevBtn) {
      els.prevBtn.addEventListener("click", () => {
        state.page = Math.max(1, state.page - 1);
        load();
      });
    }
    if (els.nextBtn) {
      els.nextBtn.addEventListener("click", () => {
        state.page += 1;
        load();
      });
    }
  });
})();
