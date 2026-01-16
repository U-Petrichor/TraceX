(() => {
  const { fetchJson, formatNumber } = window.TraceX || {};

  const els = {
    dataSelect: document.querySelector("#dataSelect"),
    modeSelect: document.querySelector("#modeSelect"),
    rebuildBtn: document.querySelector("#rebuildBtn"),
    meta: document.querySelector("#aptMeta"),
    name: document.querySelector("#aptName"),
    aliases: document.querySelector("#aptAliases"),
    mode: document.querySelector("#aptMode"),
    eventCount: document.querySelector("#aptEventCount"),
    graphScale: document.querySelector("#aptGraphScale"),
    nodeCount: document.querySelector("#aptNodeCount"),
    edgeCount: document.querySelector("#aptEdgeCount"),
    signature: document.querySelector("#aptSignature"),
    structure: document.querySelector("#aptStructure"),
    suspected: document.querySelector("#aptSuspected"),
    confidence: document.querySelector("#aptConfidence"),
    jaccard: document.querySelector("#aptJaccard"),
    recall: document.querySelector("#aptRecall"),
    ttpCount: document.querySelector("#aptTtpCount"),
    matchedTtps: document.querySelector("#aptMatchedTtps"),
    topMatches: document.querySelector("#aptTopMatches"),
    profileName: document.querySelector("#aptProfileName"),
    aliasCount: document.querySelector("#aptAliasCount"),
    profileTtpCount: document.querySelector("#aptProfileTtpCount"),
    profileAliases: document.querySelector("#aptProfileAliases"),
    profileTtps: document.querySelector("#aptProfileTtps"),
    profileIndustries: document.querySelector("#aptProfileIndustries"),
    iocGrid: document.querySelector("#aptIocGrid"),
  };

  if (!els.signature) {
    return;
  }

  const setText = (el, value) => {
    if (!el) {
      return;
    }
    el.textContent = value == null || value === "" ? "--" : String(value);
  };

  const toPercent = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return "--";
    }
    const pct = num <= 1 ? num * 100 : num;
    return `${pct.toFixed(1)}%`;
  };

  const renderTags = (container, items, tone) => {
    if (!container) {
      return;
    }
    container.innerHTML = "";
    const list = Array.isArray(items) ? items : [];
    if (!list.length) {
      const tag = document.createElement("span");
      tag.className = "apt-tag";
      tag.textContent = "暂无";
      if (tone) {
        tag.dataset.tone = tone;
      }
      container.appendChild(tag);
      return;
    }
    list.forEach((item) => {
      const tag = document.createElement("span");
      tag.className = "apt-tag";
      tag.textContent = item;
      if (tone) {
        tag.dataset.tone = tone;
      }
      container.appendChild(tag);
    });
  };

  const renderSignature = (steps) => {
    if (!els.signature) {
      return;
    }
    els.signature.innerHTML = "";
    const list = Array.isArray(steps) ? steps : [];
    if (!list.length) {
      const empty = document.createElement("div");
      empty.className = "inline-note";
      empty.textContent = "暂无攻击链签名";
      els.signature.appendChild(empty);
      return;
    }
    list.forEach((step, index) => {
      const chip = document.createElement("div");
      chip.className = "apt-chip";
      chip.textContent = step;
      els.signature.appendChild(chip);
      if (index < list.length - 1) {
        const arrow = document.createElement("span");
        arrow.className = "apt-arrow";
        arrow.textContent = "→";
        els.signature.appendChild(arrow);
      }
    });
  };

  const parseEdge = (entry) => {
    if (!entry) {
      return { raw: "-" };
    }
    if (typeof entry === "string") {
      const match = entry.match(/\[(.+?)\]\s+(.+?)\s+--(.+?)-->\s+\[(.+?)\]\s+(.+)/);
      if (match) {
        return {
          sourceType: match[1],
          sourceLabel: match[2],
          relation: match[3],
          targetType: match[4],
          targetLabel: match[5],
        };
      }
      return { raw: entry };
    }
    const source = entry.source || entry.from || entry.src || null;
    const target = entry.target || entry.to || entry.dst || null;
    const sourceType = entry.source_type || entry.sourceType || source?.type || source?.kind;
    const targetType = entry.target_type || entry.targetType || target?.type || target?.kind;
    const sourceLabel = typeof source === "string" ? source : source?.label || source?.name || source?.id;
    const targetLabel = typeof target === "string" ? target : target?.label || target?.name || target?.id;
    const relation = entry.relation || entry.edge || entry.link || "-";
    if (sourceLabel || targetLabel) {
      return {
        sourceType: sourceType || "-",
        sourceLabel: sourceLabel || "-",
        relation,
        targetType: targetType || "-",
        targetLabel: targetLabel || "-",
      };
    }
    return { raw: JSON.stringify(entry) };
  };

  const createNode = (type, label) => {
    const node = document.createElement("div");
    node.className = "apt-node";
    if (type) {
      node.dataset.type = type;
    }
    const typeEl = document.createElement("span");
    typeEl.className = "apt-node-type";
    typeEl.textContent = type ? String(type).toUpperCase() : "UNKNOWN";
    const labelEl = document.createElement("strong");
    labelEl.className = "apt-node-label";
    labelEl.textContent = label || "-";
    node.appendChild(typeEl);
    node.appendChild(labelEl);
    return node;
  };

  const renderStructure = (edges) => {
    if (!els.structure) {
      return;
    }
    els.structure.innerHTML = "";
    const list = Array.isArray(edges) ? edges : [];
    if (!list.length) {
      const empty = document.createElement("div");
      empty.className = "inline-note";
      empty.textContent = "暂无结构化路径";
      els.structure.appendChild(empty);
      return;
    }
    list.forEach((edge) => {
      const parsed = parseEdge(edge);
      const item = document.createElement("div");
      item.className = "apt-structure-item";
      if (parsed.raw) {
        item.classList.add("is-raw");
        const raw = document.createElement("div");
        raw.className = "mono";
        raw.textContent = parsed.raw;
        item.appendChild(raw);
      } else {
        const left = createNode(parsed.sourceType, parsed.sourceLabel);
        const relation = document.createElement("div");
        relation.className = "apt-relation mono";
        relation.textContent = parsed.relation;
        const right = createNode(parsed.targetType, parsed.targetLabel);
        item.appendChild(left);
        item.appendChild(relation);
        item.appendChild(right);
      }
      els.structure.appendChild(item);
    });
  };

  const renderMatches = (matches) => {
    if (!els.topMatches) {
      return;
    }
    els.topMatches.innerHTML = "";
    const list = Array.isArray(matches) ? matches : [];
    if (!list.length) {
      const empty = document.createElement("div");
      empty.className = "inline-note";
      empty.textContent = "暂无匹配结果";
      els.topMatches.appendChild(empty);
      return;
    }
    list.forEach((match) => {
      const item = document.createElement("div");
      item.className = "apt-match-item";

      const body = document.createElement("div");
      body.className = "apt-match-body";
      const title = document.createElement("strong");
      title.textContent = match.group || "未知";
      const meta = document.createElement("div");
      meta.className = "inline-note";
      const count = Array.isArray(match.matched_ttps) ? match.matched_ttps.length : 0;
      meta.textContent = `匹配 ${count} 个 TTP`;
      body.appendChild(title);
      body.appendChild(meta);

      const score = document.createElement("div");
      score.className = "apt-match-score";
      score.textContent = toPercent(match.score);

      item.appendChild(body);
      item.appendChild(score);
      els.topMatches.appendChild(item);
    });
  };

  const renderIoc = (iocMap) => {
    if (!els.iocGrid) {
      return;
    }
    els.iocGrid.innerHTML = "";
    const entries = iocMap && typeof iocMap === "object" ? Object.entries(iocMap) : [];
    if (!entries.length) {
      const empty = document.createElement("div");
      empty.className = "inline-note";
      empty.textContent = "暂无 IOC 富化数据";
      els.iocGrid.appendChild(empty);
      return;
    }
    entries.forEach(([indicator, info]) => {
      const card = document.createElement("div");
      card.className = "apt-ioc-card";
      const risk = Number(info?.risk_score ?? 0);
      card.dataset.risk = risk >= 80 ? "high" : risk >= 60 ? "medium" : "low";
      if (info?.is_malicious) {
        card.dataset.malicious = "true";
      }

      const head = document.createElement("div");
      head.className = "apt-ioc-head";

      const title = document.createElement("div");
      title.className = "apt-ioc-indicator mono";
      title.textContent = indicator;

      const score = document.createElement("div");
      score.className = "apt-ioc-risk";
      score.textContent = `风险 ${Math.round(risk)}`;

      head.appendChild(title);
      head.appendChild(score);

      const meta = document.createElement("div");
      meta.className = "apt-ioc-meta";
      const type = info?.type || "unknown";
      const geo = info?.geo || "-";
      const source = info?.source || "-";
      meta.textContent = `${type} · ${geo} · ${source}`;

      const tags = document.createElement("div");
      tags.className = "apt-tags";
      (info?.tags || []).forEach((tag) => {
        const tagEl = document.createElement("span");
        tagEl.className = "apt-tag";
        tagEl.textContent = tag;
        tags.appendChild(tagEl);
      });

      const status = document.createElement("div");
      status.className = "apt-ioc-status";
      status.textContent = info?.is_malicious ? "已标记为恶意" : "观察中";

      card.appendChild(head);
      card.appendChild(meta);
      card.appendChild(tags);
      card.appendChild(status);
      els.iocGrid.appendChild(card);
    });
  };

  const renderSummary = (report) => {
    const summary = report?.simulation || report?.summary || {};
    const profile = report?.apt_profile || {};

    const aptName = summary.name || report?.apt_name || profile?.name || "未知";
    const mode = summary.mode || report?.mode || "直接 TTP";
    const eventCount = summary.event_count ?? report?.event_count ?? 0;
    const nodeCount = summary.node_count ?? report?.node_count ?? 0;
    const edgeCount = summary.edge_count ?? report?.edge_count ?? 0;
    const total = Number(nodeCount) + Number(edgeCount);

    setText(els.name, aptName);
    setText(els.mode, mode);
    setText(els.eventCount, formatNumber ? formatNumber(eventCount) : eventCount);
    setText(els.nodeCount, formatNumber ? formatNumber(nodeCount) : nodeCount);
    setText(els.edgeCount, formatNumber ? formatNumber(edgeCount) : edgeCount);
    setText(els.graphScale, formatNumber ? formatNumber(total) : total);

    const aliases = Array.isArray(profile?.aliases) ? profile.aliases : [];
    if (aliases.length) {
      const preview = aliases.slice(0, 3).join(" / ");
      const tail = aliases.length > 3 ? ` +${aliases.length - 3}` : "";
      setText(els.aliases, `别名 ${preview}${tail}`);
    } else {
      setText(els.aliases, "别名 -");
    }

    if (els.meta) {
      const countLabel = formatNumber ? formatNumber(eventCount) : eventCount;
      els.meta.textContent = `${aptName} · ${mode} · ${countLabel} 事件`;
    }
  };

  const renderAttribution = (data) => {
    if (!data) {
      return;
    }
    setText(els.suspected, data.suspected_group || "未知");
    setText(els.confidence, toPercent(data.confidence));
    setText(els.jaccard, toPercent(data.jaccard_similarity));
    setText(els.recall, toPercent(data.recall));
    const matched = Array.isArray(data.matched_ttps) ? data.matched_ttps : [];
    renderTags(els.matchedTtps, matched);
    if (els.ttpCount) {
      els.ttpCount.textContent = `${matched.length} 个`;
    }
    renderMatches(data.top_matches);
  };

  const renderProfile = (profile) => {
    if (!profile) {
      return;
    }
    setText(els.profileName, profile.name || "未知");
    if (els.aliasCount) {
      els.aliasCount.textContent = formatNumber ? formatNumber(profile.aliases?.length || 0) : String(profile.aliases?.length || 0);
    }
    if (els.profileTtpCount) {
      els.profileTtpCount.textContent = formatNumber ? formatNumber(profile.ttps?.length || 0) : String(profile.ttps?.length || 0);
    }
    renderTags(els.profileAliases, profile.aliases, "soft");
    renderTags(els.profileTtps, profile.ttps, "accent");
    const industries = Array.isArray(profile.target_industries) && profile.target_industries.length ? profile.target_industries : [];
    renderTags(els.profileIndustries, industries, "soft");
  };

  const buildRequestUrl = (refresh) => {
    const data = els.dataSelect?.value || "APT28.jsonl";
    // const mode = els.modeSelect?.value || "direct"; // Removed mode selection
    const mode = "direct";
    const refreshFlag = refresh ? "&refresh=1" : "";
    return `/api/apt-report?mode=${encodeURIComponent(mode)}&data=${encodeURIComponent(data)}${refreshFlag}`;
  };

  const load = async (refresh = false) => {
    if (!fetchJson) {
      return;
    }
    const report = await fetchJson(buildRequestUrl(refresh));
    if (report?.error) {
      setText(els.meta, "数据加载失败");
      return;
    }
    const data = report?.report || report || {};
    renderSummary(data);
    renderSignature(data.attack_chain_signature);
    renderStructure(data.attack_chain_structure);
    renderAttribution(data.ttp_attribution);
    renderProfile(data.apt_profile);
    renderIoc(data.ioc_enrichment);
  };

  const populateSimulations = async () => {
    if (!els.dataSelect || !fetchJson) return;
    try {
      const res = await fetchJson("/api/active-simulations");
      const active = res?.active || [];
      
      // Keep existing options (TheLastTest) and append new ones
      // OR clear and rebuild. Let's keep TheLastTest as it's hardcoded in HTML now.
      // But we need to avoid duplicates if called multiple times? 
      // Current logic: just append.
      
      // Clear existing dynamic options (if any) to be safe?
      // For now, let's just append. The user expects them to appear.
      
      // Filter out what's already there?
      const existing = new Set(Array.from(els.dataSelect.options).map(o => o.value));
      
      active.forEach(filename => {
        if (existing.has(filename)) return;
        const option = document.createElement("option");
        option.value = filename;
        option.textContent = filename.replace(".jsonl", "").replace("_", " ");
        els.dataSelect.appendChild(option);
      });
      
    } catch (e) {
      console.error("Failed to fetch active simulations", e);
    }
  };

  document.addEventListener("DOMContentLoaded", async () => {
    await populateSimulations();
    load();
    if (els.dataSelect) {
      els.dataSelect.addEventListener("change", () => load(true));
    }
    if (els.modeSelect) {
      els.modeSelect.addEventListener("change", () => load(true));
    }
    if (els.rebuildBtn) {
      els.rebuildBtn.addEventListener("click", () => load(true));
    }
  });
})();
