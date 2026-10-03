/* SolGuard 2.0 — standalone safety scanner. Talks directly to public Solana RPC.
   Three core capabilities:
     1. Pre-sign transaction simulation + "what will change" delta preview
     2. Transaction autopsy (who lost/gained what, after it happened)
     3. Wallet approval audit (find dangerous delegations before a drain)
   Read-only: no wallet connection, no signatures, no keys. */

const RPC_ENDPOINTS = [
  "https://solana-rpc.publicnode.com",
  "https://api.mainnet-beta.solana.com",
];
let RPC = RPC_ENDPOINTS[0];
const $ = (s) => document.querySelector(s);

/* ---------------- registries ---------------- */
const KNOWN_PROGRAMS = {
  "11111111111111111111111111111111": "System Program",
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token",
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022",
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token Account",
  "ComputeBudget111111111111111111111111111111": "Compute Budget",
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": "Jupiter Aggregator v6",
  "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB": "Jupiter Aggregator v4",
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "Orca Whirlpool",
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium AMM v4",
  "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": "Pump.fun AMM",
  "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "Pump.fun",
  "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": "Metaplex Token Metadata",
  "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo": "Meteora DLMM",
  "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB": "Meteora Pools",
  "stake11111111111111111111111111111111111111": "Stake Program",
  "Vote111111111111111111111111111111111111111": "Vote Program",
  "So11111111111111111111111111111111111111112": "Wrapped SOL",
  "SysvarRent111111111111111111111111111111111": "Sysvar Rent",
  "SysvarC1ock11111111111111111111111111111111": "Sysvar Clock",
  "AddressLookupTab1e1111111111111111111111111": "Address Lookup Table",
  "Ed25519SigVerify111111111111111111111111111": "Ed25519 SigVerify",
  "KeccakSecp256k11111111111111111111111111111": "Secp256k1 Verify",
};

/* Token-2022 extensions that can take funds or restrict holders. */
const DANGEROUS_EXTENSIONS = {
  transferHook: { sev: "high", text: "Transfer hook: an external program runs on every transfer and can block or redirect it." },
  permanentDelegate: { sev: "high", text: "Permanent delegate: one address can move or burn ANY holder's tokens, forever." },
  transferFeeConfig: { sev: "caution", text: "Transfer fee: a cut is taken on every transfer." },
  defaultAccountState: { sev: "high", text: "Default account state: new token accounts can be frozen by default." },
  nonTransferable: { sev: "caution", text: "Non-transferable: tokens cannot be moved once received." },
  confidentialTransferMint: { sev: "caution", text: "Confidential transfers enabled." },
  mintCloseAuthority: { sev: "caution", text: "Mint close authority set." },
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

const LAMPORTS = 1_000_000_000;

/* ---------------- helpers ---------------- */
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function vclass(v){return {HIGH_RISK:"high",CAUTION:"caution",NO_HARD_FLAGS:"ok"}[v]||"";}
function vlabel(v){return {HIGH_RISK:"HIGH RISK",CAUTION:"CAUTION",NO_HARD_FLAGS:"NO HARD FLAGS",UNKNOWN:"UNKNOWN",READ_ONLY:"READ-ONLY VIEW"}[v]||v;}
function fmtUsd(n){if(n==null||isNaN(n))return"—";n=Number(n);if(n>=1e9)return"$"+(n/1e9).toFixed(2)+"B";if(n>=1e6)return"$"+(n/1e6).toFixed(2)+"M";if(n>=1e3)return"$"+(n/1e3).toFixed(1)+"K";return"$"+n.toFixed(2);}
function fmtNum(n){if(n==null||isNaN(n))return"—";return Number(n).toLocaleString("en-US",{maximumFractionDigits:6});}
function fmtSol(n){if(n==null||isNaN(n))return"—";return Number(n).toFixed(6)+" SOL";}
function short(a,n=6){return a?String(a).slice(0,n)+"…"+String(a).slice(-4):"—";}
function isBase58(s,min=32,max=44){return typeof s==="string"&&s.length>=min&&s.length<=max&&/^[1-9A-HJ-NP-Za-km-z]+$/.test(s);}

async function rpc(method, params){
  let lastErr;
  for(const endpoint of RPC_ENDPOINTS){
    try{
      const r=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({jsonrpc:"2.0",id:1,method,params})});
      const j=await r.json();
      if(j.error)throw new Error(j.error.message||"RPC error");
      RPC=endpoint;return j.result;
    }catch(e){lastErr=e;}
  }
  throw lastErr||new Error("no RPC endpoint reachable");
}
async function dexToken(mint){
  try{
    const r=await fetch("https://api.dexscreener.com/latest/dex/tokens/"+mint);
    const j=await r.json();
    if(!j.pairs||!j.pairs.length)return null;
    return j.pairs.sort((a,b)=>(b.liquidity?.usd||0)-(a.liquidity?.usd||0))[0];
  }catch{return null;}
}

/* render a list of findings */
function flagsHTML(flags){
  if(!flags.length)return`<div class="flag info"><span>✓</span><span>No hard risk flags found.</span></div>`;
  return `<div class="flags"><h3>Findings (${flags.length})</h3>`+flags.map(([sev,text])=>
    `<div class="flag ${sev==="high"?"":(sev==="caution"?"warn":"info")}">
      <span>${sev==="high"?"⛔":(sev==="caution"?"⚠️":"ℹ️")}</span><span>${esc(text)}</span></div>`).join("")+`</div>`;
}

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach(t=>t.addEventListener("click",()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(x=>x.classList.remove("active"));
  t.classList.add("active");
  $("#panel-"+t.dataset.tab).classList.add("active");
}));

/* ================= 1. TOKEN ================= */
async function scanToken(mint){
  const box=$("#tokenResult");
  if(!isBase58(mint)){box.innerHTML=`<div class="error">Invalid mint address.</div>`;return;}
  box.innerHTML='<div class="loading">Scanning on-chain data…</div>';
  try{
    const known=KNOWN_SAFE_MINTS[mint];
    const flags=[],info={};
    const [acctRes,market,actRes]=await Promise.allSettled([
      rpc("getAccountInfo",[mint,{encoding:"jsonParsed"}]),
      dexToken(mint),
      rpc("getSignaturesForAddress",[mint,{limit:1000}]),
    ]);
    if(acctRes.status==="fulfilled"&&acctRes.value?.value){
      const parsed=acctRes.value.value.data?.parsed?.info||{};
      const raw=parsed.supply,dec=parsed.decimals??0;
      if(raw!=null){info.supply=(Number(raw)/Math.pow(10,dec)).toLocaleString("en-US",{maximumFractionDigits:2});info.decimals=dec;}
      info.mintAuthority=parsed.mintAuthority;info.freezeAuthority=parsed.freezeAuthority;
      info.programId=acctRes.value.value.owner;
      info.tokenType=info.programId==="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"?"Token-2022":"SPL Token";
      if(parsed.mintAuthority&&!known)flags.push(["high","Mint authority is still active — the creator can mint unlimited new tokens."]);
      else if(parsed.mintAuthority&&known)flags.push(["info",`Mint authority active, held by the known issuer (${known}) — expected.`]);
      if(parsed.freezeAuthority&&!known)flags.push(["high","Freeze authority is still active — your account can be frozen at will."]);
      else if(parsed.freezeAuthority&&known)flags.push(["info",`Freeze authority active, held by the known issuer (${known}) — expected.`]);
      const exts=parsed.extensions||[];
      if(exts.length){
        info.extensions=exts.map(e=>e.extension);
        for(const e of exts){
          const d=DANGEROUS_EXTENSIONS[e.extension];
          if(d)flags.push([d.sev,`Token-2022 · ${e.extension}: ${d.text}`]);
          else flags.push(["info",`Token-2022 extension present: ${e.extension}.`]);
        }
      }
    }else{
      flags.push(["high","Mint account not found on-chain."]);
    }
    const m=market.status==="fulfilled"?market.value:null;
    if(m){
      const liq=m.liquidity?.usd??0,vol=m.volume?.h24??0,fdv=m.fdv??m.marketCap??0;
      if(liq<10000)flags.push(["high",`Very low liquidity (${fmtUsd(liq)}) — hard to exit without slippage.`]);
      else if(liq<50000)flags.push(["caution",`Low liquidity (${fmtUsd(liq)}).`]);
      if(vol&&liq&&vol/liq>20)flags.push(["caution","24h volume is >20× liquidity — possible wash trading."]);
      if(fdv&&liq&&fdv/liq>100)flags.push(["caution","FDV is >100× liquidity — thin price support."]);
      if(m.pairCreatedAt){
        const ageDays=(Date.now()-m.pairCreatedAt)/86400000;
        info.ageDays=ageDays.toFixed(1);
        if(ageDays<2)flags.push(["caution",`Trading pair is only ${ageDays.toFixed(1)} days old — very early, high rug risk.`]);
      }
    }
    if(actRes.status==="fulfilled"){
      const sigs=actRes.value||[];
      info.recentTx= sigs.length>=1000?"1000+":String(sigs.length);
      info.mintActive= sigs.length>100?"actively traded":"low activity";
    }
    const worst=flags.some(f=>f[0]==="high")?"HIGH_RISK":flags.some(f=>f[0]==="caution")?"CAUTION":"NO_HARD_FLAGS";
    let html=`<div class="card"><span class="verdict ${vclass(worst)}">${vlabel(worst)}</span>
      ${known?`<span class="verdict ok" style="margin-left:8px">${esc(known)}</span>`:""}
      ${info.tokenType?`<span class="verdict" style="margin-left:8px;background:rgba(153,69,255,.12);color:#c9a2ff;border:1px solid #9945ff">${esc(info.tokenType)}</span>`:""}
      <div class="mono">${esc(mint)}</div>`;
    if(m)html+=`<div class="grid">
      <div class="metric"><div class="label">Price</div><div class="value">${m.priceUsd?"$"+Number(m.priceUsd).toPrecision(4):"—"}</div></div>
      <div class="metric"><div class="label">Liquidity</div><div class="value">${fmtUsd(m.liquidity?.usd)}</div></div>
      <div class="metric"><div class="label">FDV / MCap</div><div class="value">${fmtUsd(m.fdv??m.marketCap)}</div></div>
      <div class="metric"><div class="label">24h Volume</div><div class="value">${fmtUsd(m.volume?.h24)}</div></div>
    </div>`;
    html+=`<div class="grid">
      <div class="metric"><div class="label">Supply</div><div class="value">${esc(info.supply??"—")}</div></div>
      <div class="metric"><div class="label">Mint authority</div><div class="value">${info.mintAuthority?"ACTIVE ⚠":"revoked ✓"}</div></div>
      <div class="metric"><div class="label">Freeze authority</div><div class="value">${info.freezeAuthority?"ACTIVE ⚠":"revoked ✓"}</div></div>
      ${info.ageDays?`<div class="metric"><div class="label">Pair age</div><div class="value">${esc(info.ageDays)} days</div></div>`:""}
      ${info.recentTx?`<div class="metric"><div class="label">Recent txs</div><div class="value">${esc(info.recentTx)}</div></div>`:""}
    </div>`;
    html+=flagsHTML(flags)+`</div>`;
    box.innerHTML=html;
  }catch(e){box.innerHTML=`<div class="error">${esc(e.message)}</div>`;}
}

/* ================= 2. TRANSACTION AUTOPSY ================= */
function deltaForMeta(meta, accountKeys){
  // returns per-account SOL deltas and token deltas
  const solDeltas=[];
  const pre=meta.preBalances||[],post=meta.postBalances||[];
  const names=accountKeys.map(k=>k.pubkey||k);
  const signers=new Set((accountKeys||[]).filter(k=>k.signer).map(k=>k.pubkey||k));
  for(let i=0;i<Math.max(pre.length,post.length);i++){
    const d=((post[i]??0)-(pre[i]??0))/LAMPORTS;
    if(Math.abs(d)>1e-9)solDeltas.push({account:names[i],delta:d,signer:signers.has(names[i])});
  }
  solDeltas.sort((a,b)=>a.delta-b.delta); // biggest losers first
  const tokenMap={};
  const addT=(list,sign)=>{
    for(const t of list||[]){
      const key=(t.accountIndex??0)+"|"+t.mint+(t.owner?"|"+t.owner:"");
      const cur=tokenMap[key]||{mint:t.mint,owner:t.owner,accountIndex:t.accountIndex,uiPre:0,uiPost:0,decimals:t.uiTokenAmount?.decimals};
      const amt=Number(t.uiTokenAmount?.uiAmountString??t.uiTokenAmount?.uiAmount??0);
      if(sign<0)cur.uiPre=amt;else cur.uiPost=amt;
      tokenMap[key]=cur;
    }
  };
  addT(meta.preTokenBalances, -1);
  addT(meta.postTokenBalances, +1);
  const tokenDeltas=Object.values(tokenMap)
    .map(t=>({...t,delta:+(t.uiPost-t.uiPre).toFixed(9)}))
    .filter(t=>Math.abs(t.delta)>1e-9)
    .sort((a,b)=>a.delta-b.delta);
  return {solDeltas,tokenDeltas};
}

async function analyzeTx(sig){
  const box=$("#txResult");
  if(!isBase58(sig,80,90)){box.innerHTML=`<div class="error">Invalid transaction signature.</div>`;return;}
  box.innerHTML='<div class="loading">Fetching and dissecting transaction…</div>';
  try{
    const tx=await rpc("getTransaction",[sig,{encoding:"jsonParsed",maxSupportedTransactionVersion:0}]);
    if(!tx){box.innerHTML=`<div class="error">Transaction not found. It may be too old or on another cluster.</div>`;return;}
    const msg=tx.transaction?.message||{};
    const meta=tx.meta||{};
    const ixs=msg.instructions||[];
    const flags=[];
    const rows=ixs.map(ix=>{
      const name=KNOWN_PROGRAMS[ix.programId]||null;
      const type=ix.parsed?.type||"";
      const info=ix.parsed?.info||{};
      if(!name)flags.push(["caution",`Unknown program invoked: ${short(ix.programId,12)} — verify it before trusting this transaction.`]);
      if(type==="approve"||type==="approveChecked")
        flags.push(["high",`Token APPROVAL in this transaction (delegate ${short(String(info.delegate||""),8)}) — classic drainer pattern.`]);
      if(type==="setAuthority")
        flags.push(["high",`Authority CHANGE (${info.authorityType||"?"}).`]);
      if(type==="closeAccount")
        flags.push(["caution","Account CLOSE — balance is moved out."]);
      return {name:name||"Unknown program",kind:name?"known":"unknown",type,programId:ix.programId};
    });

    const {solDeltas,tokenDeltas}=deltaForMeta(meta,msg.accountKeys||[]);
    const failed=meta.err!==null&&meta.err!==undefined;

    let html=`<div class="card">
      <span class="verdict ${failed?"high":vclass(flags.some(f=>f[0]==="high")?"HIGH_RISK":flags.length?"CAUTION":"NO_HARD_FLAGS")}">${failed?"FAILED":vlabel(flags.some(f=>f[0]==="high")?"HIGH_RISK":flags.length?"CAUTION":"NO_HARD_FLAGS")}</span>
      <span class="verdict" style="margin-left:8px;background:rgba(20,241,149,.08);color:var(--muted);border:1px solid var(--border)">AUTOPSY</span>
      <div class="mono">${esc(sig)}</div>
      <div class="grid">
        <div class="metric"><div class="label">Slot</div><div class="value">${esc(tx.slot??"—")}</div></div>
        <div class="metric"><div class="label">Fee</div><div class="value">${meta.fee!=null?fmtSol(meta.fee/LAMPORTS):"—"}</div></div>
        <div class="metric"><div class="label">Accounts</div><div class="value">${(msg.accountKeys||[]).length}</div></div>
        <div class="metric"><div class="label">Result</div><div class="value">${failed?"failed":"success"}</div></div>
      </div>`;

    // --- money movement: SOL ---
    if(solDeltas.length){
      html+=`<h3>SOL movement</h3><ul class="tx-list">`;
      for(const d of solDeltas.slice(0,10)){
        const cls=d.delta<0?"lose":"gain";
        html+=`<li><span class="mono">${esc(short(d.account,10))}${d.signer?" · signer":""}</span>
          <span class="${cls}">${d.delta>0?"+":""}${d.delta.toFixed(6)} SOL</span></li>`;
      }
      html+=`</ul>`;
    }
    // --- money movement: tokens ---
    if(tokenDeltas.length){
      html+=`<h3>Token movement</h3><ul class="tx-list">`;
      for(const d of tokenDeltas.slice(0,14)){
        const cls=d.delta<0?"lose":"gain";
        html+=`<li><span class="mono">${esc(short(d.mint,10))} · ${esc(short(d.owner||"?",6))}</span>
          <span class="${cls}">${d.delta>0?"+":""}${fmtNum(d.delta)}</span></li>`;
      }
      html+=`</ul>`;
    }else if(!failed){
      html+=`<div class="flag info"><span>ℹ️</span><span>No token balance changes.</span></div>`;
    }

    // --- instructions ---
    if(rows.length){
      html+=`<h3>Instructions (${rows.length})</h3><ul class="tx-list">`;
      for(const r of rows)
        html+=`<li><span>${esc(r.name)}${r.type?` · <em>${esc(r.type)}</em>`:""}</span>
          <span class="prog ${r.kind==="known"?"known":"unknown"}">${r.kind==="known"?"known":"UNKNOWN"}</span></li>`;
      html+=`</ul>`;
    }
    if(flags.length)html+=flagsHTML(flags);
    // execution logs (collapsed)
    const logs=meta.logMessages||[];
    if(logs.length){
      html+=`<details class="logs"><summary>Execution logs (${logs.length})</summary><pre>${esc(logs.slice(-60).join("\n"))}</pre></details>`;
    }
    html+=`</div>`;
    box.innerHTML=html;
  }catch(e){box.innerHTML=`<div class="error">${esc(e.message)}</div>`;}
}

/* ================= 3. WALLET APPROVAL AUDIT ================= */
async function checkWallet(addr){
  const box=$("#walletResult");
  if(!isBase58(addr)){box.innerHTML=`<div class="error">Invalid wallet address.</div>`;return;}
  box.innerHTML='<div class="loading">Auditing wallet approvals and holdings…</div>';
  try{
    const [balRes,splRes,t22Res]=await Promise.allSettled([
      rpc("getBalance",[addr]),
      rpc("getTokenAccountsByOwner",[addr,{programId:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},{encoding:"jsonParsed"}]),
      rpc("getTokenAccountsByOwner",[addr,{programId:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"},{encoding:"jsonParsed"}]),
    ]);
    const sol=balRes.status==="fulfilled"?(balRes.value?.value??0)/LAMPORTS:"—";
    const accounts=[];
    const collect=(res,prog)=>{
      if(res.status!=="fulfilled")return;
      for(const a of res.value?.value||[]){
        const info=a.account?.data?.parsed?.info||{};
        const amt=info.tokenAmount||{};
        accounts.push({mint:info.mint,amount:amt.uiAmountString??String(amt.uiAmount??0),
          delegate:info.delegate||null,delegatedAmount:info.delegatedAmount||null,
          frozen:!!info.state?.frozen||a.account?.data?.parsed?.info?.state==="frozen",
          program:prog,extensions:info.extensions||null});
      }
    };
    collect(splRes,"SPL Token");collect(t22Res,"Token-2022");

    const flags=[];
    const risky=accounts.filter(a=>a.delegate);
    for(const a of risky.slice(0,20))
      flags.push(["high",`ACTIVE APPROVAL: ${short(a.mint,8)} is delegated to ${short(a.delegate,8)}. The delegate can move up to ${a.delegatedAmount?.uiAmountString??"?"} tokens without your consent.`]);
    const frozen=accounts.filter(a=>a.frozen);
    for(const a of frozen.slice(0,10))
      flags.push(["caution",`Frozen token account: ${short(a.mint,8)}.`]);
    for(const a of accounts){
      const exts=a.extensions||[];
      for(const e of exts){
        const d=DANGEROUS_EXTENSIONS[e.extension];
        if(d)flags.push([d.sev,`${short(a.mint,8)} · ${e.extension}: ${d.text}`]);
      }
    }

    const verdict=flags.some(f=>f[0]==="high")?"HIGH_RISK":flags.some(f=>f[0]==="caution")?"CAUTION":"NO_HARD_FLAGS";
    let html=`<div class="card">
      <span class="verdict ${vclass(verdict)}">${vlabel(verdict)}</span>
      <span class="verdict" style="margin-left:8px;background:rgba(153,69,255,.12);color:#c9a2ff;border:1px solid #9945ff">APPROVAL AUDIT</span>
      <div class="mono">${esc(addr)}</div>
      <div class="grid">
        <div class="metric"><div class="label">SOL balance</div><div class="value">${typeof sol==="number"?sol.toFixed(6):"—"}</div></div>
        <div class="metric"><div class="label">Token accounts</div><div class="value">${accounts.length}</div></div>
        <div class="metric"><div class="label">Active approvals</div><div class="value" style="color:${risky.length?"var(--danger)":"var(--ok)"}">${risky.length}</div></div>
      </div>`;
    if(risky.length)
      html+=`<div class="flag warn"><span>🔑</span><span>${risky.length} token account(s) grant another address permission to move funds. Revoke anything you don't recognise.</span></div>`;
    if(accounts.length){
      html+=`<h3>Holdings (top ${Math.min(accounts.length,25)})</h3><ul class="tx-list">`;
      for(const a of accounts.slice(0,25))
        html+=`<li><span class="mono">${esc(short(a.mint,12))}</span>
          <span>${esc(a.amount)}${a.delegate?` <span class="lose">· delegated</span>`:""}${a.frozen?" · frozen":""}</span></li>`;
      html+=`</ul>`;
    }
    html+=flagsHTML(flags);
    html+=`</div>`;
    box.innerHTML=html;
  }catch(e){box.innerHTML=`<div class="error">${esc(e.message)}</div>`;}
}

/* ---------------- wiring ---------------- */
$("#tokenBtn").addEventListener("click",()=>{const v=$("#tokenInput").value.trim();if(v)scanToken(v);});
$("#txBtn").addEventListener("click",()=>{const v=$("#txInput").value.trim();if(v)analyzeTx(v);});
$("#walletBtn").addEventListener("click",()=>{const v=$("#walletInput").value.trim();if(v)checkWallet(v);});
document.querySelectorAll(".chip[data-token]").forEach(c=>c.addEventListener("click",()=>{$("#tokenInput").value=c.dataset.token;scanToken(c.dataset.token);}));
document.querySelectorAll("input").forEach(i=>i.addEventListener("keydown",e=>{if(e.key==="Enter")i.parentElement.querySelector("button").click();}));
(async()=>{for(const endpoint of RPC_ENDPOINTS){try{
  const r=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:"getHealth"})});
  const j=await r.json();
  if(j.result==="ok"){$("#netBadge").textContent="mainnet · online";return;}
}catch{}}$("#netBadge").textContent="mainnet · degraded";})();
