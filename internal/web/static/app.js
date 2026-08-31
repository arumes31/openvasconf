"use strict";

document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

const currentPath = window.location.pathname;
document.querySelectorAll(".primary-nav a").forEach((link) => {
  const linkPath = new URL(link.href, window.location.origin).pathname;
  const customerDetail = linkPath === "/" && currentPath.startsWith("/customers/") && currentPath !== "/customers/new";
  const nestedPage = linkPath !== "/" && linkPath !== "/customers/new" && currentPath.startsWith(`${linkPath}/`);
  if (currentPath === linkPath || customerDetail || nestedPage) link.setAttribute("aria-current", "page");
});

const densityToggle = document.querySelector("[data-density-toggle]");
if (densityToggle) {
  const applyComfortable = (enabled) => {
    document.body.classList.toggle("comfortable-view", enabled);
    densityToggle.setAttribute("aria-pressed", String(enabled));
    densityToggle.textContent = enabled ? "Compact density" : "Relax density";
  };
  applyComfortable(window.localStorage.getItem("openvasconf-density") === "comfortable");
  densityToggle.addEventListener("click", () => {
    const enabled = !document.body.classList.contains("comfortable-view");
    window.localStorage.setItem("openvasconf-density", enabled ? "comfortable" : "compact");
    applyComfortable(enabled);
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
      setText("[data-op-task]", current ? `${current.name} / ${current.status} / ${current.progress}%` : "No scans currently running");
      const latest = data.tasks.find((task) => task.last_report);
      setText("[data-op-recent]", latest ? `Latest: ${latest.name} / ${latest.status} / severity ${latest.last_report.severity}` : "No completed report returned");
      setText("[data-op-feeds]", String(data.feeds.length));
      const versions = data.feeds.map((feed) => {
        const age = feed.updated_at ? Math.floor((Date.now() - Date.parse(feed.updated_at)) / 86400000) : null;
        return `${feed.name}: ${feed.version || "unknown"}${age === null ? "" : ` (${age}d old)`}`;
      }).join(" / ");
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

const updaterPanel = document.querySelector("[data-updater-status-url]");
if (updaterPanel) {
  let updaterRefreshInFlight = false;
  let updaterTimer = null;
  let idleRefreshes = 0;
  const activeDelay = 2000;
  const warmIdleDelay = 10000;
  const coldIdleDelay = 30000;

  const renderPhaseElapsed = () => {
    const activePanel = document.querySelector("[data-update-phase-start]");
    const output = document.querySelector("[data-update-elapsed]");
    if (!activePanel || !output) return;
    const started = Date.parse(activePanel.dataset.updatePhaseStart);
    if (Number.isNaN(started)) {
      output.textContent = "unknown";
      return;
    }
    const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainder = seconds % 60;
    output.textContent = hours > 0 ? `${hours}h ${minutes}m ${remainder}s` :
      (minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`);
  };

  const scheduleUpdaterRefresh = (delay) => {
    window.clearTimeout(updaterTimer);
    if (!document.hidden) updaterTimer = window.setTimeout(refreshUpdater, delay);
  };

  const refreshUpdater = () => {
    if (document.hidden || updaterRefreshInFlight) return;
    updaterRefreshInFlight = true;
    fetch(updaterPanel.dataset.updaterStatusUrl, {headers: {"Accept": "application/json"}})
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Updater unavailable");
        const active = Boolean(data.active);
        idleRefreshes = active ? 0 : idleRefreshes + 1;
        document.querySelectorAll("[data-update-state]").forEach((element) => {
          element.textContent = active ? data.active.state : "IDLE";
        });
        document.querySelectorAll("[data-update-phase]").forEach((element) => {
          element.textContent = active ? data.active.phase : "no active mutation";
        });
        document.querySelectorAll("[data-update-detail]").forEach((element) => {
          element.textContent = active ? data.active.detail : "";
        });
        const activePanel = document.querySelector("[data-update-phase-start]");
        if (activePanel && active) {
          activePanel.dataset.updatePhaseStart = data.active.phase_started_at || data.active.started_at;
        }
        renderPhaseElapsed();
        scheduleUpdaterRefresh(active ? activeDelay : (idleRefreshes <= 3 ? warmIdleDelay : coldIdleDelay));
      })
      .catch(() => {
        idleRefreshes++;
        document.querySelectorAll("[data-update-state]").forEach((element) => {
          element.textContent = "OFFLINE";
        });
        document.querySelectorAll("[data-update-phase]").forEach((element) => {
          element.textContent = "status unavailable";
        });
        document.querySelectorAll("[data-update-detail]").forEach((element) => {
          element.textContent = "";
        });
        scheduleUpdaterRefresh(coldIdleDelay);
      })
      .finally(() => {
        updaterRefreshInFlight = false;
      });
  };
  document.addEventListener("visibilitychange", () => {
    window.clearTimeout(updaterTimer);
    if (!document.hidden) refreshUpdater();
  });
  window.setInterval(renderPhaseElapsed, 1000);
  renderPhaseElapsed();
  refreshUpdater();
}
