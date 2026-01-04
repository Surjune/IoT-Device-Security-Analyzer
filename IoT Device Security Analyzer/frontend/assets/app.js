/* ===============================
   GLOBAL STATE
================================ */
let ALL_DEVICES = [];
let SCAN_RUNNING = false;

/* ===============================
   API HELPER
================================ */
async function api(path, options = {}) {
  const res = await fetch(path, options);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

/* ===============================
   STATUS HELPERS
================================ */
function setStatus(text) {
  const el = document.getElementById("scan-status");
  if (el) el.textContent = text;
}

/* ===============================
   LOAD DATA
================================ */
async function loadData() {
  try {
    setStatus("Loading scan results...");
    const data = await api("/api/risk");

    renderSummary(data.summary || {});
    ALL_DEVICES = data.devices || [];
    renderDevices(ALL_DEVICES);

    loadDevicePresence(); // ✅ ADD THIS LINE (STEP 2)
    loadRiskTrend();


    setStatus("Results updated.");
  } catch (err) {
    setStatus("Failed to load results.");
    console.error(err);
  }
}


/* ===============================
   SUMMARY RENDER
================================ */
function renderSummary(summary) {
  const container = document.getElementById("summary");
  if (!container) return;

  const green = summary.Green || 0;
  const yellow = summary.Yellow || 0;
  const red = summary.Red || 0;

  container.innerHTML = `
    <div class="summary-box green">Green<br>${green}</div>
    <div class="summary-box yellow">Yellow<br>${yellow}</div>
    <div class="summary-box red">Red<br>${red}</div>
  `;
}

/* ===============================
   DEVICE TABLE RENDER
================================ */
function renderDevices(devices) {
  const container = document.getElementById("devices");
  if (!container) return;

  if (!devices.length) {
    container.innerHTML = "<em>No IoT devices detected.</em>";
    return;
  }

  let html = `
    <table>
      <thead>
        <tr>
          <th>IP Address</th>
          <th>Device Name</th>
          <th>Device Type</th>
          <th>Open Ports</th>
          <th>Password Status</th> 
          <th>Security Recommendation</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
  `;
  
devices.forEach(d => {
  html += `
    <tr>
      <td>${d.ip}</td>
      <td>${d.name || "-"}</td>
      <td>${d.device_type || "Unknown"}</td>
      <td>${d.open_ports || "-"}</td>

      <!-- ✅ PASSWORD STATUS COLUMN -->
      <td>
        <span class="pill ${d.password_status === "Weak Password" ? "Red" : "Green"}">
          ${d.password_status || "-"}
        </span>
      </td>

      <!-- ✅ SECURITY RECOMMENDATION COLUMN -->
      <td>${d.security_issues || "-"}</td>

      <!-- ✅ RISK COLUMN -->
      <td>
        <span class="pill ${d.risk_level}">
          ${d.risk_level} (${d.risk_score})
        </span>
      </td>
    </tr>
  `;
});

  container.innerHTML = html;
}

/* ===============================
   SEARCH FILTER
================================ */
function filterDevices(query) {
  const q = query.toLowerCase().trim();

  if (!q) {
    renderDevices(ALL_DEVICES);
    return;
  }

  const filtered = ALL_DEVICES.filter(d =>
    d.ip.toLowerCase().includes(q) ||
    (d.name || "").toLowerCase().includes(q) ||
    (d.device_type || "").toLowerCase().includes(q)

  );

  renderDevices(filtered);
}

/* ===============================
   SCAN CONTROL
================================ */
async function startScan() {
  if (SCAN_RUNNING) return;

  try {
    SCAN_RUNNING = true;
    setStatus("Scan running...");

    await api("/api/scan/start", { method: "POST" });

    while (true) {
      const status = await api("/api/scan/status");

      if (status.status === "finished") {
        setStatus("Scan completed.");
        break;
      }

      if (status.status === "failed") {
        setStatus("Scan failed.");
        break;
      }

      await new Promise(r => setTimeout(r, 2000));
    }

    await loadData();
  } catch (err) {
    setStatus("Error during scan.");
    console.error(err);
  } finally {
    SCAN_RUNNING = false;
  }
}

/* ===============================
   EVENT BINDINGS
================================ */
document.getElementById("btn-scan")
  ?.addEventListener("click", startScan);

document.getElementById("btn-refresh")
  ?.addEventListener("click", loadData);

document.getElementById("btn-status")
  ?.addEventListener("click", async () => {
    try {
      const s = await api("/api/scan/status");
      setStatus(JSON.stringify(s));
    } catch (err) {
      setStatus("Failed to fetch scan status.");
    }
  });

document.getElementById("deviceSearch")
  ?.addEventListener("input", e => {
    filterDevices(e.target.value);
  });
// existing code
// existing functions
// existing event listeners



// ===============================
// DEVICE PRESENCE (SCAN HISTORY)
// ===============================

function loadDevicePresence() {
  fetch("/api/device-presence")
    .then(res => res.json())
    .then(data => {
      const tbody = document.getElementById("devicePresenceBody");
      if (!tbody) return;

      tbody.innerHTML = "";

      if (!data || data.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align:center;color:#777;font-size:14px">
              No device presence data available
            </td>
          </tr>`;
        return;
      }

      data.forEach(d => {
        const tr = document.createElement("tr");

        tr.innerHTML = `
          <td>${d.ip}</td>
          <td>${d.name || "-"}</td>
          <td>${d.type || "-"}</td>
          <td>${formatTimestamp(d.first_seen)}</td>
          <td>${formatTimestamp(d.last_seen)}</td>
          <td>${renderStatusBadge(d.status)}</td>
        `;

        tbody.appendChild(tr);
      });
    })
    .catch(err => {
      console.error("Error loading device presence:", err);
    });
}

// STEP 2 helpers
function formatTimestamp(ts) {
  if (!ts) return "-";
  const last = new Date(ts + "Z");
  const now = new Date();
  const diffMs = now - last;
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} min ago`;

  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} hr ago`;

  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? "s" : ""} ago`;
}

function renderStatusBadge(status) {
  if (status === "Active") {
    return `<span class="pill Green">Active</span>`;
  }
  if (status === "New Device") {
    return `<span class="pill Yellow">New</span>`;
  }
  return `<span class="pill Red">Offline</span>`;
}

let riskChart = null;

async function loadRiskTrend() {
  try {
    const data = await api("/api/risk-trend");

    const labels = data.map(d => d.time);
    const values = data.map(d => d.avg_risk);

    const ctx = document.getElementById("riskChart");
    if (!ctx) return;

    if (riskChart) {
      riskChart.destroy();
    }

    riskChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Average Network Risk",
          data: values,
          borderColor: "#d32f2f",
          backgroundColor: "rgba(211,47,47,0.1)",
          tension: 0.3,
          fill: true
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            min: 0,
            max: 10,
            ticks: {
              callback: v => v.toFixed(1)
            }
          }
        }
      }
    });

  } catch (err) {
    console.error("Failed to load risk trend", err);
  }
}

// STEP 3 call on page load


/* ===============================
   INITIAL LOAD
================================ */
loadData();
loadDevicePresence();
