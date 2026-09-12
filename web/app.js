/**
 * Zero Trust Network Access (ZTNA) Gateway Showcase Engine
 * NIST SP 800-207 Interactive Policy Evaluation & Telemetry Console
 */

// =============================================================================
// Personas & Security Credentials
// =============================================================================
const PERSONAS = {
  alice: {
    id: "alice",
    name: "Alice Vance",
    title: "Finance Lead & Controller",
    department: "Finance",
    clearance: "Tier-1 High Sensitivity",
    email: "alice@corp.local",
    roles: ["finance-admin", "user"],
    tokenType: "Bearer (RS256 Signed)",
    isExpired: false,
    avatarBg: "from-emerald-500 to-teal-700"
  },
  bob: {
    id: "bob",
    name: "Bob Miller",
    title: "Staff Platform Engineer",
    department: "Engineering",
    clearance: "Tier-2 Internal Dev",
    email: "bob@corp.local",
    roles: ["engineering", "user"],
    tokenType: "Bearer (RS256 Signed)",
    isExpired: false,
    avatarBg: "from-indigo-500 to-violet-700"
  },
  charlie: {
    id: "charlie",
    name: "Charlie Davis",
    title: "Lead Compliance Auditor",
    department: "Internal Audit",
    clearance: "Audit Read-Only",
    email: "charlie@corp.local",
    roles: ["auditor", "user"],
    tokenType: "Bearer (RS256 Signed)",
    isExpired: false,
    avatarBg: "from-amber-500 to-orange-700"
  },
  eve: {
    id: "eve",
    name: "Eve Jenkins",
    title: "External Contractor / Guest",
    department: "Guest / Unprivileged",
    clearance: "Tier-3 Public",
    email: "eve@corp.local",
    roles: ["user"],
    tokenType: "Bearer (RS256 Signed)",
    isExpired: false,
    avatarBg: "from-purple-500 to-pink-700"
  },
  anonymous: {
    id: "anonymous",
    name: "Unauthenticated Client",
    title: "No Credentials Provided",
    department: "Internet / External",
    clearance: "None",
    email: "",
    roles: [],
    tokenType: "None",
    isExpired: false,
    avatarBg: "from-slate-600 to-slate-800"
  },
  expired: {
    id: "expired",
    name: "Alice (Expired Session)",
    title: "Finance Lead (Session Timed Out)",
    department: "Finance",
    clearance: "Expired",
    email: "alice@corp.local",
    roles: ["finance-admin", "user"],
    tokenType: "Bearer (Expired exp claim)",
    isExpired: true,
    avatarBg: "from-rose-500 to-red-800"
  }
};

// =============================================================================
// Target Microservices & Endpoints
// =============================================================================
const ENDPOINTS = {
  finance_ledger: {
    path: "/api/finance/ledger",
    method: "GET",
    service: "Finance Core API (finance_api:5001)",
    tier: "HIGH_SENSITIVITY",
    description: "Corporate financial transactions & general ledger records",
    mockPayload: {
      service: "finance_api",
      security_classification: "RESTRICTED-TIER-1",
      total_records: 3,
      ledger: [
        { id: "TX-1001", date: "2026-09-01", desc: "Cloud Infrastructure Payment", amount: 45200.0, status: "SETTLED" },
        { id: "TX-1002", date: "2026-09-05", desc: "ZTNA Gateway License Renewal", amount: 18500.0, status: "SETTLED" },
        { id: "TX-1003", date: "2026-09-10", desc: "Hardware Security Module (HSM)", amount: 62000.0, status: "PENDING" }
      ]
    }
  },
  finance_payout: {
    path: "/api/finance/payout",
    method: "POST",
    service: "Finance Core API (finance_api:5001)",
    tier: "HIGH_SENSITIVITY",
    description: "Execute wire transfer & high-value payout",
    mockPayload: {
      status: "SUCCESS",
      transaction: {
        id: "TX-1004",
        amount: 50000.0,
        currency: "USD",
        recipient: "Cybersecurity Vendor Corp",
        status: "APPROVED_AND_EXECUTED"
      }
    }
  },
  dev_repos: {
    path: "/api/dev/repositories",
    method: "GET",
    service: "Developer Portal (dev_portal:5002)",
    tier: "MEDIUM_SENSITIVITY",
    description: "Engineering Git repositories & CI pipeline statuses",
    mockPayload: {
      service: "dev_portal",
      repositories_count: 3,
      repositories: [
        { id: "repo-01", name: "zero-trust-identity-aware-gateway", branch: "main", build: "PASSING" },
        { id: "repo-02", name: "core-ledger-engine", branch: "main", build: "PASSING" },
        { id: "repo-03", name: "iam-policy-engine-rego", branch: "main", build: "PASSING" }
      ]
    }
  },
  dev_deploys: {
    path: "/api/dev/deployments",
    method: "GET",
    service: "Developer Portal (dev_portal:5002)",
    tier: "MEDIUM_SENSITIVITY",
    description: "Kubernetes production & staging active deployment clusters",
    mockPayload: {
      service: "dev_portal",
      clusters: [
        { env: "production", k8s_cluster: "k8s-prod-us-east-1", replicas: 3, health: "HEALTHY" },
        { env: "staging", k8s_cluster: "k8s-stage-us-east-1", replicas: 2, health: "HEALTHY" }
      ]
    }
  },
  healthz: {
    path: "/healthz",
    method: "GET",
    service: "Envoy Gateway (envoy:8443)",
    tier: "PUBLIC",
    description: "Gateway health check endpoint (bypasses authorization)",
    mockPayload: {
      status: "healthy",
      gateway: "envoy_pep",
      uptime: "99.999%",
      timestamp: new Date().toISOString()
    }
  }
};

// =============================================================================
// Current Simulator State
// =============================================================================
let simulatorState = {
  personaKey: "alice",
  endpointKey: "finance_ledger",
  devicePosture: {
    encrypted: true,
    os: "linux",
    patch_level: "current",
    corporate_managed: true
  }
};

// =============================================================================
// Security Audit Logs
// =============================================================================
let auditLogs = [
  {
    id: "AUD-8921",
    timestamp: "12:30:14 UTC",
    user: "alice",
    roles: ["finance-admin", "user"],
    ip: "192.168.10.42",
    resource: "/api/finance/ledger",
    method: "GET",
    decision: "ALLOW",
    posture: "encrypted=true,os=linux,patch=current,mdm=true",
    violations: []
  },
  {
    id: "AUD-8920",
    timestamp: "12:28:55 UTC",
    user: "bob",
    roles: ["engineering", "user"],
    ip: "10.200.1.15",
    resource: "/api/finance/ledger",
    method: "GET",
    decision: "DENY",
    posture: "encrypted=true,os=linux,patch=current,mdm=true",
    violations: ["Access denied: Missing required role for Finance API"]
  },
  {
    id: "AUD-8919",
    timestamp: "12:25:02 UTC",
    user: "alice",
    roles: ["finance-admin", "user"],
    ip: "172.16.88.9",
    resource: "/api/finance/ledger",
    method: "GET",
    decision: "DENY",
    posture: "encrypted=false,os=linux,patch=current,mdm=true",
    violations: ["Device Posture Violation: Disk encryption is disabled"]
  },
  {
    id: "AUD-8918",
    timestamp: "12:21:40 UTC",
    user: "bob",
    roles: ["engineering", "user"],
    ip: "10.200.1.15",
    resource: "/api/dev/repositories",
    method: "GET",
    decision: "ALLOW",
    posture: "encrypted=true,os=windows_11,patch=current,mdm=true",
    violations: []
  }
];

let stats = {
  totalEvaluations: 4,
  allowed: 2,
  denied: 2
};

let decisionChartInstance = null;

// =============================================================================
// Client-Side OPA Rego Decision Engine (Direct Mirror of policies/main.rego)
// =============================================================================
function evaluateZeroTrustPolicy(persona, posture, endpoint) {
  const isPublic = endpoint.path === "/healthz" || endpoint.path.startsWith("/api/public");
  
  // Public bypasses all auth & posture
  if (isPublic) {
    return {
      allowed: true,
      statusCode: 200,
      violations: [],
      headers: {
        "X-ZTNA-Policy": "NIST-SP-800-207-PUBLIC",
        "X-Auth-Decision": "ALLOWED"
      },
      responseBody: endpoint.mockPayload
    };
  }

  // 1. Authentication Check
  if (persona.id === "anonymous") {
    return {
      allowed: false,
      statusCode: 401,
      violations: ["Authentication required: Missing or invalid JWT credentials"],
      headers: { "WWW-Authenticate": 'Bearer realm="ztna-gateway"' },
      responseBody: {
        status: "UNAUTHORIZED",
        error: "AuthenticationRequired",
        detail: "Missing Bearer JWT Authorization header",
        target_resource: endpoint.path
      }
    };
  }

  if (persona.isExpired) {
    return {
      allowed: false,
      statusCode: 401,
      violations: ["Authentication required: JWT access token expired"],
      headers: { "WWW-Authenticate": 'Bearer realm="ztna-gateway"' },
      responseBody: {
        status: "UNAUTHORIZED",
        error: "TokenExpired",
        detail: "JWT expiration timestamp has elapsed",
        target_resource: endpoint.path
      }
    };
  }

  const violations = [];

  // 2. RBAC Microsegmentation Check (rbac.rego)
  let rbacAllowed = false;
  const isFinance = endpoint.path.startsWith("/api/finance");
  const isDev = endpoint.path.startsWith("/api/dev");
  const hasFinanceRole = persona.roles.includes("finance-admin") || persona.roles.includes("finance");
  const hasEngineeringRole = persona.roles.includes("engineering") || persona.roles.includes("developer");
  const hasAuditorRole = persona.roles.includes("auditor");

  if (isFinance) {
    if (endpoint.method === "GET" && (hasFinanceRole || hasAuditorRole)) {
      rbacAllowed = true;
    } else if (["POST", "PUT", "DELETE", "PATCH"].includes(endpoint.method) && hasFinanceRole) {
      rbacAllowed = true;
    } else {
      if (["POST", "PUT", "DELETE", "PATCH"].includes(endpoint.method) && !hasFinanceRole) {
        violations.push("Access denied: Mutation operations on Finance API require finance-admin role");
      } else {
        violations.push("Access denied: Missing required role for Finance API");
      }
    }
  } else if (isDev) {
    if (hasEngineeringRole) {
      rbacAllowed = true;
    } else {
      violations.push("Access denied: Missing required role for Developer Portal");
    }
  } else {
    violations.push("Access denied: Unrecognized target resource");
  }

  // 3. Device Posture Evaluation (posture.rego)
  let postureAllowed = true;
  const validOperatingSystems = ["linux", "darwin", "macos", "windows", "windows_10", "windows_11"];

  if (!posture.encrypted) {
    postureAllowed = false;
    violations.push("Device Posture Violation: Disk encryption is disabled");
  }

  if (posture.patch_level !== "current") {
    postureAllowed = false;
    violations.push("Device Posture Violation: Operating system patch level is outdated");
  }

  if (!validOperatingSystems.includes(posture.os)) {
    postureAllowed = false;
    violations.push("Device Posture Violation: Unsupported or untrusted operating system");
  }

  // High-sensitivity endpoints require corporate MDM management
  if (endpoint.tier === "HIGH_SENSITIVITY" && !posture.corporate_managed) {
    postureAllowed = false;
    violations.push("Device Posture Violation: Unmanaged or non-corporate device for Tier-1 API");
  }

  const overallAllowed = rbacAllowed && postureAllowed;

  if (overallAllowed) {
    return {
      allowed: true,
      statusCode: 200,
      violations: [],
      headers: {
        "X-User-Id": persona.id,
        "X-User-Roles": persona.roles.join(","),
        "X-Auth-Decision": "ALLOWED",
        "X-ZTNA-Policy": "NIST-SP-800-207"
      },
      responseBody: {
        ...endpoint.mockPayload,
        caller_identity: {
          user: persona.id,
          roles: persona.roles,
          decision: "ALLOWED"
        }
      }
    };
  } else {
    return {
      allowed: false,
      statusCode: 403,
      violations: violations,
      headers: {},
      responseBody: {
        status: "DENIED",
        error: "AccessDeniedByPolicy",
        framework: "NIST-SP-800-207",
        user: persona.id,
        target_resource: endpoint.path,
        method: endpoint.method,
        policy_violations: violations,
        device_posture_evaluated: posture,
        timestamp: new Date().toISOString()
      }
    };
  }
}

// =============================================================================
// DOM Manipulation & Event Handlers
// =============================================================================
document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide Icons
  if (window.lucide) {
    lucide.createIcons();
  }

  // Init Chart
  initChart();

  // Setup Event Listeners
  setupPersonaSelectors();
  setupPostureSwitches();
  setupEndpointSelectors();
  setupSimulationButton();
  setupTabs();

  // Initial Sync
  updatePersonaUI();
  updateCurlPreview();
  renderAuditLogs();
});

function setupPersonaSelectors() {
  const personaCards = document.querySelectorAll(".persona-card");
  personaCards.forEach(card => {
    card.addEventListener("click", () => {
      personaCards.forEach(c => c.classList.remove("border-violet-500", "bg-violet-950/30"));
      card.classList.add("border-violet-500", "bg-violet-950/30");
      simulatorState.personaKey = card.dataset.persona;
      updatePersonaUI();
      updateCurlPreview();
    });
  });
}

function updatePersonaUI() {
  const p = PERSONAS[simulatorState.personaKey];
  const display = document.getElementById("active-persona-display");
  if (!display) return;

  display.innerHTML = `
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr ${p.avatarBg} flex items-center justify-center font-bold text-white shadow-md">
        ${p.name.charAt(0)}
      </div>
      <div>
        <div class="font-semibold text-white text-sm flex items-center gap-2">
          ${p.name}
          <span class="text-xs px-2 py-0.5 rounded-full bg-violet-900/60 border border-violet-500/30 text-violet-300">
            ${p.department}
          </span>
        </div>
        <div class="text-xs text-slate-400 font-code mt-0.5">
          Roles: <span class="text-indigo-300">${p.roles.length ? p.roles.join(", ") : "none"}</span>
        </div>
      </div>
    </div>
  `;

  // Update Decoded Token Viewer
  updateTokenViewer(p);
}

function setupPostureSwitches() {
  const encToggle = document.getElementById("posture-encrypted");
  const osSelect = document.getElementById("posture-os");
  const patchSelect = document.getElementById("posture-patch");
  const mdmToggle = document.getElementById("posture-mdm");

  if (encToggle) {
    encToggle.addEventListener("change", (e) => {
      simulatorState.devicePosture.encrypted = e.target.checked;
      updateCurlPreview();
    });
  }

  if (osSelect) {
    osSelect.addEventListener("change", (e) => {
      simulatorState.devicePosture.os = e.target.value;
      updateCurlPreview();
    });
  }

  if (patchSelect) {
    patchSelect.addEventListener("change", (e) => {
      simulatorState.devicePosture.patch_level = e.target.value;
      updateCurlPreview();
    });
  }

  if (mdmToggle) {
    mdmToggle.addEventListener("change", (e) => {
      simulatorState.devicePosture.corporate_managed = e.target.checked;
      updateCurlPreview();
    });
  }
}

function setupEndpointSelectors() {
  const endpointSelect = document.getElementById("target-endpoint-select");
  if (endpointSelect) {
    endpointSelect.addEventListener("change", (e) => {
      simulatorState.endpointKey = e.target.value;
      updateCurlPreview();
    });
  }
}

function setupSimulationButton() {
  const btn = document.getElementById("btn-run-simulation");
  if (!btn) return;

  btn.addEventListener("click", () => {
    // Run Evaluation
    const persona = PERSONAS[simulatorState.personaKey];
    const posture = simulatorState.devicePosture;
    const endpoint = ENDPOINTS[simulatorState.endpointKey];

    // Animate flow line
    const flowLine = document.getElementById("flow-indicator");
    if (flowLine) {
      flowLine.classList.add("flow-gradient");
      setTimeout(() => flowLine.classList.remove("flow-gradient"), 1500);
    }

    const decision = evaluateZeroTrustPolicy(persona, posture, endpoint);

    // Update Stats
    stats.totalEvaluations++;
    if (decision.allowed) stats.allowed++;
    else stats.denied++;
    updateStatsDisplay();

    // Create Audit Log Entry
    const newLog = {
      id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toLocaleTimeString() + " UTC",
      user: persona.id,
      roles: persona.roles,
      ip: "172.24.0." + Math.floor(2 + Math.random() * 250),
      resource: endpoint.path,
      method: endpoint.method,
      decision: decision.allowed ? "ALLOW" : "DENY",
      posture: `encrypted=${posture.encrypted},os=${posture.os},patch=${posture.patch_level},mdm=${posture.corporate_managed}`,
      violations: decision.violations
    };
    auditLogs.unshift(newLog);
    if (auditLogs.length > 25) auditLogs.pop();
    renderAuditLogs();

    // Render Result
    renderDecisionResult(decision, persona, endpoint, posture);
  });
}

function renderDecisionResult(decision, persona, endpoint, posture) {
  const container = document.getElementById("decision-result-container");
  if (!container) return;

  const isAllowed = decision.allowed;
  const statusColor = isAllowed ? "text-emerald-400" : (decision.statusCode === 401 ? "text-amber-400" : "text-rose-400");
  const bgGlow = isAllowed ? "glow-emerald border-emerald-500/30" : (decision.statusCode === 401 ? "glow-indigo border-amber-500/30" : "glow-rose border-rose-500/30");
  const badgeBg = isAllowed ? "bg-emerald-950/80 text-emerald-300 border-emerald-500/40" : "bg-rose-950/80 text-rose-300 border-rose-500/40";

  let violationsHtml = "";
  if (decision.violations.length > 0) {
    violationsHtml = `
      <div class="mt-4 p-3 rounded-lg bg-rose-950/30 border border-rose-500/30">
        <div class="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
          <i data-lucide="shield-alert" class="w-4 h-4"></i> NIST SP 800-207 Policy Violations Detected:
        </div>
        <ul class="list-disc list-inside space-y-1 text-xs text-rose-200">
          ${decision.violations.map(v => `<li>${v}</li>`).join("")}
        </ul>
      </div>
    `;
  }

  let headersHtml = "";
  if (Object.keys(decision.headers).length > 0) {
    headersHtml = `
      <div class="mt-4 p-3 rounded-lg bg-slate-950/70 border border-slate-800">
        <div class="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-1.5">
          Injected Envoy Downstream Headers:
        </div>
        <pre class="font-code text-xs text-slate-300 overflow-x-auto">${Object.entries(decision.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="glass-card p-5 border ${bgGlow} transition-all duration-300">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div class="flex items-center gap-2.5">
          <span class="text-xs font-bold font-code px-2.5 py-1 rounded-md border ${badgeBg}">
            HTTP ${decision.statusCode} ${isAllowed ? "ALLOWED" : "BLOCKED"}
          </span>
          <span class="text-xs text-slate-400 font-code">
            ${endpoint.method} ${endpoint.path}
          </span>
        </div>
        <span class="text-xs text-slate-500 font-code">
          Decision Engine: OPA Rego v1
        </span>
      </div>

      <div class="mt-4">
        <h4 class="text-sm font-semibold text-white flex items-center gap-2">
          ${isAllowed ? '<i data-lucide="check-circle" class="w-4 h-4 text-emerald-400"></i> Access Authorized by Envoy PEP' : '<i data-lucide="x-circle" class="w-4 h-4 text-rose-400"></i> Request Rejected by Policy Decision Point'}
        </h4>
        <p class="text-xs text-slate-400 mt-1">
          ${isAllowed ? 'User identity, roles, and device posture fully satisfy zero trust policies.' : 'Access denied: Policy Enforcement Point terminated request before reaching internal microservice.'}
        </p>
      </div>

      ${violationsHtml}
      ${headersHtml}

      <div class="mt-4">
        <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
          Microservice Response Payload:
        </div>
        <pre class="p-3 rounded-lg bg-slate-950 font-code text-xs text-slate-200 overflow-x-auto max-h-48 border border-slate-800/80">${JSON.stringify(decision.responseBody, null, 2)}</pre>
      </div>
    </div>
  `;

  if (window.lucide) lucide.createIcons();
}

function updateCurlPreview() {
  const persona = PERSONAS[simulatorState.personaKey];
  const posture = simulatorState.devicePosture;
  const endpoint = ENDPOINTS[simulatorState.endpointKey];
  const preview = document.getElementById("curl-preview-code");
  if (!preview) return;

  const postureHeader = `encrypted=${posture.encrypted},os=${posture.os},patch_level=${posture.patch_level},corporate_managed=${posture.corporate_managed}`;
  const authHeader = persona.id !== "anonymous" ? ` \\\n  -H "Authorization: Bearer <${persona.id.toUpperCase()}_JWT_TOKEN>"` : "";

  const cmd = `curl -k -i -X ${endpoint.method} "https://localhost:8443${endpoint.path}"${authHeader} \\\n  -H "X-Device-Posture: ${postureHeader}"`;
  preview.textContent = cmd;
}

function updateTokenViewer(persona) {
  const container = document.getElementById("jwt-claims-display");
  if (!container) return;

  const now = Math.floor(Date.now() / 1000);
  const jwtMock = {
    header: {
      alg: "RS256",
      typ: "JWT",
      kid: "ztna-keycloak-2026-rsa"
    },
    payload: {
      iss: "http://keycloak:8080/realms/ztna-realm",
      sub: persona.id === "anonymous" ? "none" : `user-uuid-${persona.id}-0091`,
      preferred_username: persona.id,
      email: persona.email,
      department: persona.department,
      clearance: persona.clearance,
      iat: now - 300,
      exp: persona.isExpired ? now - 100 : now + 3300,
      realm_access: {
        roles: persona.roles
      }
    }
  };

  container.textContent = JSON.stringify(jwtMock, null, 2);
}

function renderAuditLogs(filter = "ALL") {
  const tbody = document.getElementById("audit-logs-tbody");
  if (!tbody) return;

  const filtered = filter === "ALL" 
    ? auditLogs 
    : auditLogs.filter(l => l.decision === filter);

  tbody.innerHTML = filtered.map(log => {
    const isAllow = log.decision === "ALLOW";
    const badge = isAllow 
      ? '<span class="px-2 py-0.5 rounded text-[11px] font-code font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/30">ALLOW</span>'
      : '<span class="px-2 py-0.5 rounded text-[11px] font-code font-bold bg-rose-950 text-rose-400 border border-rose-500/30">DENY</span>';

    return `
      <tr class="border-b border-slate-800/60 hover:bg-slate-900/40 text-xs font-code transition-colors">
        <td class="py-2.5 px-3 text-slate-400">${log.timestamp}</td>
        <td class="py-2.5 px-3 text-white font-semibold">${log.user}</td>
        <td class="py-2.5 px-3 text-slate-400">${log.ip}</td>
        <td class="py-2.5 px-3 text-indigo-300">${log.method} ${log.resource}</td>
        <td class="py-2.5 px-3">${badge}</td>
        <td class="py-2.5 px-3 text-slate-400 truncate max-w-xs" title="${log.violations.length ? log.violations.join('; ') : log.posture}">
          ${log.violations.length ? `<span class="text-rose-400">${log.violations[0]}</span>` : log.posture}
        </td>
      </tr>
    `;
  }).join("");
}

function updateStatsDisplay() {
  const elTotal = document.getElementById("stat-total");
  const elAllowed = document.getElementById("stat-allowed");
  const elDenied = document.getElementById("stat-denied");

  if (elTotal) elTotal.textContent = stats.totalEvaluations;
  if (elAllowed) elAllowed.textContent = stats.allowed;
  if (elDenied) elDenied.textContent = stats.denied;

  if (decisionChartInstance) {
    decisionChartInstance.data.datasets[0].data = [stats.allowed, stats.denied];
    decisionChartInstance.update();
  }
}

function initChart() {
  const ctx = document.getElementById("decisionRatioChart");
  if (!ctx || !window.Chart) return;

  decisionChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Allowed", "Denied"],
      datasets: [{
        data: [stats.allowed, stats.denied],
        backgroundColor: ["#10b981", "#f43f5e"],
        borderColor: ["#060814", "#060814"],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 11 } }
        }
      },
      cutout: "70%"
    }
  });
}

function setupTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => {
        b.classList.remove("text-violet-400", "border-violet-500", "bg-violet-950/40");
        b.classList.add("text-slate-400", "border-transparent");
      });
      btn.classList.add("text-violet-400", "border-violet-500", "bg-violet-950/40");
      btn.classList.remove("text-slate-400", "border-transparent");

      const target = btn.dataset.tab;
      tabContents.forEach(content => {
        content.classList.toggle("hidden", content.id !== target);
      });
    });
  });
}

// Copy to clipboard helper
window.copyToClipboard = function(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    alert("Copied to clipboard!");
  });
};
