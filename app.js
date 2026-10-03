/* SolGuard — standalone frontend. Talks directly to public Solana RPC + DexScreener.
   No backend, no wallet, no keys. Read-only. */

const RPC_ENDPOINTS = [
  "https://solana-rpc.publicnode.com",
  "https://api.mainnet-beta.solana.com",
];
let RPC = RPC_ENDPOINTS[0];
const $ = (sel) => document.querySelector(sel);

/* ---------- tabs ---------- */
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("#panel-" + tab.dataset.tab).classList.add("active");
  });
});

/* ---------- known registries ---------- */
const KNOWN_PROGRAMS = {
  "11111111111111111111111111111111": ["System Program", "core"],
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": ["SPL Token", "core"],
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": ["Token-2022", "core"],
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": ["Associated Token Account", "core"],
  "ComputeBudget111111111111111111111111111111": ["Compute Budget", "core"],
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": ["Jupiter Aggregator v6", "dex"],
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": ["Orca Whirlpool", "dex"],
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": ["Raydium AMM v4", "dex"],
  "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": ["Pump.fun AMM", "dex"],
  "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": ["Pump.fun", "launchpad"],
  "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": ["Metaplex Token Metadata", "nft"],
  "stake11111111111111111111111111111111111111": ["Stake Program", "core"],
  "Vote111111111111111111111111111111111111111": ["Vote Program", "core"],
};

const KNOWN_SAFE_MINTS = {
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC (Circle)",
  "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT (Tether)",
  "So11111111111111111111111111111111111111112": "wSOL (Wrapped SOL)",
  "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": "BONK",
  "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN": "JUP (Jupiter)",
  "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So": "mSOL (Marinade)",
  "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": "RAY (Raydium)",
  "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE": "ORCA",
};

/* ---------- helpers ---------- */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function verdictClass(v) {
  return { HIGH_RISK: "high", CAUTION: "caution", NO_HARD_FLAGS: "ok" }[v] || "";
}
function verdictLabel(v) {
  return { HIGH_RISK: "HIGH RISK", CAUTION: "CAUTION", NO_HARD_FLAGS: "NO HARD FLAGS",
           UNKNOWN: "UNKNOWN" }[v] || v;
}
function fmtUsd(n) {
  if (n == null || isNaN(n)) return "—";
  n = Number(n);
  if (n >= 1e9) return "$" + (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6) return "$" + (n / 1e6).toFixed(2) + "M";
  if (n >= 1e3) return "$" + (n / 1e3).toFixed(1) + "K";
  return "$" + n.toFixed(2);
}
function isBase58(s, min = 32, max = 44) {
  return typeof s === "string" && s.length >= min && s.length <= max &&
         /^[1-9A-HJ-NP-Za-km-z]+$/.test(s);
}
async function rpc(method, params) {
  let lastErr;
  for (const endpoint of RPC_ENDPOINTS) {
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const j = await r.json();
      if (j.error) throw new Error(j.error.message || "RPC error");
      RPC = endpoint; // remember a working endpoint
      return j.result;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("no RPC endpoint reachable");
}
async function dexToken(mint) {
  try {
    const r = await fetch("https://api.dexscreener.com/latest/dex/tokens/" + mint);
    const j = await r.json();
    if (!j.pairs || !j.pairs.length) return null;
    return j.pairs.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];
  } catch { return null; }
}

/* ---------- token analysis ---------- */
async function scanToken(mint) {
  const box = $("#tokenResult");
  if (!isBase58(mint)) { box.innerHTML = `<div class="error">Invalid mint address.</div>`; return; }
  box.innerHTML = '<div class="loading">Scanning on-chain data…</div>';
  try {
    const known = KNOWN_SAFE_MINTS[mint];
    const flags = [];
    const info = {};

    const [acctRes, market] = await Promise.allSettled([
      rpc("getAccountInfo", [mint, { encoding: "jsonParsed" }]),
      dexToken(mint),
    ]);

    if (acctRes.status === "fulfilled" && acctRes.value?.value) {
      const parsed = acctRes.value.value.data?.parsed?.info || {};
      // parsed mint account carries supply + decimals directly
      const rawSupply = parsed.supply;
      const decimals = parsed.decimals ?? 0;
      if (rawSupply != null) {
        info.supply = (Number(rawSupply) / Math.pow(10, decimals)).toLocaleString("en-US", { maximumFractionDigits: 2 });
        info.decimals = decimals;
      }
      info.mintAuthority = parsed.mintAuthority;
      info.freezeAuthority = parsed.freezeAuthority;
      if (parsed.mintAuthority && !known)
        flags.push(["high", "Mint authority is still active — the creator can mint unlimited new tokens."]);
      else if (parsed.mintAuthority && known)
        flags.push(["info", `Mint authority active, held by the known issuer (${known}) — expected.`]);
      if (parsed.freezeAuthority && !known)
        flags.push(["high", "Freeze authority is still active — accounts can be frozen at will."]);
      else if (parsed.freezeAuthority && known)
        flags.push(["info", `Freeze authority active, held by the known issuer (${known}) — expected.`]);
    } else {
      flags.push(["high", "Mint account not found on-chain."]);
    }

    const m = market.status === "fulfilled" ? market.value : null;
    if (m) {
      const liq = m.liquidity?.usd ?? 0;
      const vol = m.volume?.h24 ?? 0;
      const fdv = m.fdv ?? m.marketCap ?? 0;
      if (liq < 10000) flags.push(["high", `Very low liquidity (${fmtUsd(liq)}) — hard to exit without slippage.`]);
      else if (liq < 50000) flags.push(["caution", `Low liquidity (${fmtUsd(liq)}).`]);
      if (vol && liq && vol / liq > 20) flags.push(["caution", "24h volume is >20× liquidity — possible wash trading."]);
      if (fdv && liq && fdv / liq > 100) flags.push(["caution", "FDV is >100× liquidity — thin price support."]);
    }

    const worst = flags.some(f => f[0] === "high") ? "HIGH_RISK"
                : flags.some(f => f[0] === "caution") ? "CAUTION"
                : "NO_HARD_FLAGS";

    let html = `<div class="card">
      <span class="verdict ${verdictClass(worst)}">${verdictLabel(worst)}</span>
      ${known ? `<span class="verdict ok" style="margin-left:8px">${esc(known)}</span>` : ""}
      <div class="mono">${esc(mint)}</div>`;
    if (m) {
      html += `<div class="grid">
        <div class="metric"><div class="label">Price</div><div class="value">${m.priceUsd ? "$" + Number(m.priceUsd).toPrecision(4) : "—"}</div></div>
        <div class="metric"><div class="label">Liquidity</div><div class="value">${fmtUsd(m.liquidity?.usd)}</div></div>
        <div class="metric"><div class="label">FDV / MCap</div><div class="value">${fmtUsd(m.fdv ?? m.marketCap)}</div></div>
        <div class="metric"><div class="label">24h Volume</div><div class="value">${fmtUsd(m.volume?.h24)}</div></div>
      </div>`;
    }
    html += `<div class="grid">
      <div class="metric"><div class="label">Supply</div><div class="value">${esc(info.supply ?? "—")}</div></div>
      <div class="metric"><div class="label">Mint authority</div><div class="value">${info.mintAuthority ? "ACTIVE ⚠" : "revoked ✓"}</div></div>
      <div class="metric"><div class="label">Freeze authority</div><div class="value">${info.freezeAuthority ? "ACTIVE ⚠" : "revoked ✓"}</div></div>
    </div>`;
    if (flags.length) {
      html += `<div class="flags"><h3>Findings (${flags.length})</h3>`;
      for (const [sev, text] of flags) {
        html += `<div class="flag ${sev === "high" ? "" : (sev === "caution" ? "warn" : "info")}">
          <span>${sev === "high" ? "⛔" : (sev === "caution" ? "⚠️" : "ℹ️")}</span><span>${esc(text)}</span></div>`;
      }
      html += `</div>`;
    } else {
      html += `<div class="flag info"><span>✓</span><span>No hard risk flags from supply, authorities or market data.</span></div>`;
    }
    box.innerHTML = html + `</div>`;
  } catch (e) {
    box.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

/* ---------- transaction analysis ---------- */
async function analyzeTx(sig) {
  const box = $("#txResult");
  if (!isBase58(sig, 80, 90)) { box.innerHTML = `<div class="error">Invalid transaction signature.</div>`; return; }
  box.innerHTML = '<div class="loading">Fetching transaction…</div>';
  try {
    const tx = await rpc("getTransaction", [sig, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }]);
    if (!tx) { box.innerHTML = `<div class="error">Transaction not found.</div>`; return; }
    const msg = tx.transaction?.message || {};
    const ixs = msg.instructions || [];
    const flags = [];
    const rows = ixs.map(ix => {
      const [name, kind] = KNOWN_PROGRAMS[ix.programId] || ["Unknown program", "unknown"];
      const type = ix.parsed?.type || "";
      const info = ix.parsed?.info || {};
      if (kind === "unknown")
        flags.push(["caution", `Unknown program invoked: ${ix.programId.slice(0, 12)}… — verify before signing.`]);
      if (type === "approve" || type === "approveChecked")
        flags.push(["high", `Token APPROVAL (delegate ${String(info.delegate).slice(0, 8)}…) — classic drainer pattern. Delegate can move your tokens.`]);
      if (type === "setAuthority")
        flags.push(["high", `Authority CHANGE (${info.authorityType}).`]);
      return { name, kind, type, known: kind !== "unknown" };
    });
    const meta = tx.meta || {};
    const worst = flags.some(f => f[0] === "high") ? "HIGH_RISK"
                : flags.length ? "CAUTION" : "NO_HARD_FLAGS";
    let html = `<div class="card">
      <span class="verdict ${verdictClass(worst)}">${verdictLabel(worst)}</span>
      <div class="mono">${esc(sig)}</div>
      <div class="grid">
        <div class="metric"><div class="label">Status</div><div class="value">${meta.err === null ? "success" : "failed"}</div></div>
        <div class="metric"><div class="label">Fee</div><div class="value">${meta.fee != null ? (meta.fee / 1e9).toFixed(6) + " SOL" : "—"}</div></div>
        <div class="metric"><div class="label">Accounts</div><div class="value">${(msg.accountKeys || []).length}</div></div>
      </div>`;
    if (rows.length) {
      html += `<h3>Instructions (${rows.length})</h3><ul class="tx-list">`;
      for (const r of rows)
        html += `<li><span>${esc(r.name)}${r.type ? ` · <em>${esc(r.type)}</em>` : ""}</span>
          <span class="prog ${r.known ? "known" : "unknown"}">${r.known ? "known" : "UNKNOWN"}</span></li>`;
      html += `</ul>`;
    }
    if (flags.length) {
      html += `<div class="flags"><h3>Warnings</h3>`;
      for (const [sev, text] of flags)
        html += `<div class="flag ${sev === "high" ? "" : "warn"}"><span>${sev === "high" ? "⛔" : "⚠️"}</span><span>${esc(text)}</span></div>`;
      html += `</div>`;
    }
    box.innerHTML = html + `</div>`;
  } catch (e) {
    box.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

/* ---------- wallet ---------- */
async function checkWallet(addr) {
  const box = $("#walletResult");
  if (!isBase58(addr)) { box.innerHTML = `<div class="error">Invalid wallet address.</div>`; return; }
  box.innerHTML = '<div class="loading">Checking wallet…</div>';
  try {
    const [balRes, accRes] = await Promise.allSettled([
      rpc("getBalance", [addr]),
      rpc("getTokenAccountsByOwner", [addr, { programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" }, { encoding: "jsonParsed" }]),
    ]);
    const sol = balRes.status === "fulfilled" ? (balRes.value?.value ?? 0) / 1e9 : "—";
    const tokens = [];
    if (accRes.status === "fulfilled") {
      for (const a of accRes.value?.value || []) {
        const info = a.account?.data?.parsed?.info || {};
        const amt = info.tokenAmount || {};
        if (amt.uiAmount) tokens.push({ mint: info.mint, amount: amt.uiAmountString });
      }
    }
    let html = `<div class="card">
      <span class="verdict ${verdictClass("NO_HARD_FLAGS")}">READ-ONLY VIEW</span>
      <div class="mono">${esc(addr)}</div>
      <div class="grid">
        <div class="metric"><div class="label">SOL balance</div><div class="value">${typeof sol === "number" ? sol.toFixed(6) : "—"}</div></div>
        <div class="metric"><div class="label">Token accounts</div><div class="value">${tokens.length}</div></div>
      </div>`;
    if (tokens.length) {
      html += `<h3>Tokens (top ${Math.min(tokens.length, 20)})</h3><ul class="tx-list">`;
      for (const t of tokens.slice(0, 20))
        html += `<li><span class="mono">${esc(t.mint)}</span><span>${esc(t.amount)}</span></li>`;
      html += `</ul>`;
    }
    box.innerHTML = html + `</div>`;
  } catch (e) {
    box.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

/* ---------- wiring ---------- */
$("#tokenBtn").addEventListener("click", () => {
  const v = $("#tokenInput").value.trim();
  if (v) scanToken(v);
});
$("#txBtn").addEventListener("click", () => {
  const v = $("#txInput").value.trim();
  if (v) analyzeTx(v);
});
$("#walletBtn").addEventListener("click", () => {
  const v = $("#walletInput").value.trim();
  if (v) checkWallet(v);
});
document.querySelectorAll(".chip[data-token]").forEach((c) =>
  c.addEventListener("click", () => { $("#tokenInput").value = c.dataset.token; scanToken(c.dataset.token); }));
document.querySelectorAll("input").forEach((i) =>
  i.addEventListener("keydown", (e) => {
    if (e.key === "Enter") i.parentElement.querySelector("button").click();
  }));

/* connectivity badge */
(async () => {
  for (const endpoint of RPC_ENDPOINTS) {
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getHealth" }),
      });
      const j = await r.json();
      if (j.result === "ok") { $("#netBadge").textContent = "mainnet · online"; return; }
    } catch {}
  }
  $("#netBadge").textContent = "mainnet · degraded";
})();
