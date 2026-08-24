"use strict";

document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

const compactToggle = document.querySelector("[data-compact-toggle]");
if (compactToggle) {
  const applyCompact = (enabled) => {
    document.body.classList.toggle("compact-view", enabled);
    compactToggle.textContent = enabled ? "Comfortable view" : "Compact view";
  };
  applyCompact(window.localStorage.getItem("openvasconf-compact") === "1");
  compactToggle.addEventListener("click", () => {
    const enabled = !document.body.classList.contains("compact-view");
    window.localStorage.setItem("openvasconf-compact", enabled ? "1" : "0");
    applyCompact(enabled);
  });
}

const networkArea = document.querySelector("#networks");
const normalizeNetworks = (value) => {
  const fields = value.split(/[\n\r,;]+/).map((entry) => entry.trim()).filter(Boolean);
  return [...new Set(fields.map((entry) => {
    const commentIndex = entry.indexOf("#");
    const network = (commentIndex === -1 ? entry : entry.slice(0, commentIndex)).trim();
    const comment = commentIndex === -1 ? "" : entry.slice(commentIndex).trim();
    if (!network) return "";
    const normalized = (network.includes("/") || network.includes("-")) ? network : `${network}/32`;
    return comment ? `${normalized} ${comment}` : normalized;
  }).filter(Boolean))].join("\n");
};
const networkFile = document.querySelector("[data-network-file]");
if (networkFile && networkArea) {
  networkFile.addEventListener("change", async () => {
    const file = networkFile.files[0];
    if (!file) return;
    networkArea.value = normalizeNetworks(await file.text());
  });
}
const copyNormalized = document.querySelector("[data-copy-normalized]");
if (copyNormalized && networkArea) {
  copyNormalized.addEventListener("click", async () => {
    const normalized = normalizeNetworks(networkArea.value);
    networkArea.value = normalized;
    await navigator.clipboard.writeText(normalized);
    copyNormalized.textContent = "Copied normalized list";
  });
}

const operationsPanel = document.querySelector("[data-operations-url]");
if (operationsPanel) {
  const setText = (selector, value) => {
    const element = operationsPanel.querySelector(selector);
    if (element) element.textContent = value;
  };
  fetch(operationsPanel.dataset.operationsUrl, {headers: {"Accept": "application/json"}})
    .then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Live status unavailable");
      setText("[data-op-latency]", `${Math.round(data.latency_ns / 1000000)} ms`);
      setText("[data-op-active]", String(data.active_tasks.length));
      const current = data.active_tasks[0];
      setText("[data-op-task]", current ? `${current.name} · ${current.status} · ${current.progress}%` : "No scans currently running");
	  const latest = data.tasks.find((task) => task.last_report);
	  setText("[data-op-recent]", latest ? `Latest: ${latest.name} · ${latest.status} · severity ${latest.last_report.severity}` : "No completed report returned");
      setText("[data-op-feeds]", String(data.feeds.length));
	  const versions = data.feeds.map((feed) => {
	    const age = feed.updated_at ? Math.floor((Date.now() - Date.parse(feed.updated_at)) / 86400000) : null;
	    return `${feed.name}: ${feed.version || "unknown"}${age === null ? "" : ` (${age}d old)`}`;
	  }).join(" · ");
      setText("[data-op-feed-age]", versions || "No feed records returned");
    })
    .catch((error) => {
      setText("[data-op-latency]", "Unavailable");
      setText("[data-op-task]", error.message);
      setText("[data-op-feed-age]", "Check GMP connection and feed objects");
    });
}

const syncingRows = document.querySelectorAll("tr[data-customer-id] [data-progress-cell]");
if (syncingRows.length) {
  window.setInterval(() => {
    syncingRows.forEach((cell) => {
      const row = cell.closest("tr");
      fetch(`/api/customers/${encodeURIComponent(row.dataset.customerId)}/progress`)
        .then((response) => response.ok ? response.json() : null)
        .then((data) => {
          if (!data || data.status !== "syncing") return;
          const progress = data.progress;
          const heading = cell.querySelector("strong");
          const meter = cell.querySelector("progress");
          if (heading) heading.textContent = progress.Phase || "syncing";
          if (meter) {
            meter.max = progress.TotalOperations || 1;
            meter.value = progress.CompletedOperations || 0;
          }
        });
    });
  }, 3000);
}
