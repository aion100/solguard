#!/usr/bin/env python3
"""
SolGuard — Solana safety scanner. Backend API.

Read-only analysis of tokens, transactions and wallets using public Solana
RPC + known program registry. No wallet connection, no signatures, no keys.

Endpoints:
    GET /api/health
    GET /api/token/<mint>
    GET /api/tx/<signature>
    GET /api/wallet/<address>

Run:
    python server.py --port 8080
"""

import argparse
import json
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RPC = "https://api.mainnet-beta.solana.com"
TIMEOUT = 20

# --- known programs (safety context) ---
KNOWN_PROGRAMS = {
    "11111111111111111111111111111111": ("System Program", "core"),
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": ("SPL Token", "core"),
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": ("Token-2022", "core"),
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": ("Associated Token Account", "core"),
    "ComputeBudget111111111111111111111111111111": ("Compute Budget", "core"),
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": ("Jupiter Aggregator v6", "dex"),
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": ("Orca Whirlpool", "dex"),
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": ("Raydium AMM v4", "dex"),
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": ("Pump.fun AMM", "dex"),
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": ("Pump.fun", "launchpad"),
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": ("Metaplex Token Metadata", "nft"),
    "stake11111111111111111111111111111111111111": ("Stake Program", "core"),
    "Vote111111111111111111111111111111111111111": ("Vote Program", "core"),
}

DANGEROUS_AUTHORITY_HINTS = [
    "mint authority still active",
    "freeze authority still active",
]

# Well-known mints where an active authority is expected (issuer-controlled).
KNOWN_SAFE_MINTS = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC (Circle)",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT (Tether)",
    "So11111111111111111111111111111111111111112": "wSOL (Wrapped SOL)",
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": "BONK",
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN": "JUP (Jupiter)",
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So": "mSOL (Marinade)",
    "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj": "stSOL (Lido)",
    "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1": "bSOL (BlazeStake)",
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": "RAY (Raydium)",
    "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE": "ORCA",
}

SUSPICIOUS_TX_HINTS = {
    "setAuthority": "changes token authority (privilege change)",
    "Approve": "grants a delegate permission over your tokens (drainer pattern)",
    "CloseAccount": "closes an account and moves its balance",
    "TransferChecked": "token transfer",
}


def rpc(method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = json.loads(r.read())
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "rpc error"))
    return data.get("result")


def is_base58(s: str, min_len=32, max_len=44) -> bool:
    if not (min_len <= len(s) <= max_len):
        return False
    return bool(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s))


def analyze_token(mint: str) -> dict:
    out = {"mint": mint, "flags": [], "verdict": "UNKNOWN", "info": {}}
    known = KNOWN_SAFE_MINTS.get(mint)
    if known:
        out["info"]["known_token"] = known
    # supply
    try:
        supply = rpc("getTokenSupply", [mint])
        if supply:
            out["info"]["supply"] = supply.get("value", {}).get("uiAmountString")
            out["info"]["decimals"] = supply.get("value", {}).get("decimals")
    except Exception as exc:
        out["error"] = f"supply lookup failed: {exc}"
    # accounts (mint + freeze authority live in parsed account data)
    try:
        acc = rpc("getAccountInfo", [mint, {"encoding": "jsonParsed"}])
        if acc and acc.get("value"):
            parsed = (acc["value"].get("data") or {}).get("parsed", {}).get("info", {})
            mint_auth = parsed.get("mintAuthority")
            freeze_auth = parsed.get("freezeAuthority")
            out["info"]["mintAuthority"] = mint_auth
            out["info"]["freezeAuthority"] = freeze_auth
            # For known issuer-controlled tokens, active authority is expected.
            if mint_auth and not known:
                out["flags"].append({
                    "severity": "high",
                    "text": "Mint authority is still active — the creator can mint unlimited new tokens.",
                })
            elif mint_auth and known:
                out["flags"].append({
                    "severity": "info",
                    "text": f"Mint authority active, held by the known issuer ({known}) — expected.",
                })
            if freeze_auth and not known:
                out["flags"].append({
                    "severity": "high",
                    "text": "Freeze authority is still active — accounts can be frozen at will.",
                })
            elif freeze_auth and known:
                out["flags"].append({
                    "severity": "info",
                    "text": f"Freeze authority active, held by the known issuer ({known}) — expected.",
                })
        else:
            out["flags"].append({"severity": "high", "text": "Mint account not found on-chain."})
    except Exception as exc:
        out["flags"].append({"severity": "info", "text": f"Authority lookup failed: {exc}"})

    sev = [f["severity"] for f in out["flags"]]
    if "high" in sev:
        out["verdict"] = "HIGH_RISK"
    elif "caution" in sev:
        out["verdict"] = "CAUTION"
    elif "error" not in out:
        out["verdict"] = "NO_HARD_FLAGS"
    return out


def analyze_tx(signature: str) -> dict:
    out = {"signature": signature, "flags": [], "verdict": "UNKNOWN", "instructions": []}
    try:
        tx = rpc("getTransaction", [signature, {"encoding": "jsonParsed",
                                                "maxSupportedTransactionVersion": 0}])
    except Exception as exc:
        out["error"] = str(exc)
        return out
    if not tx:
        out["error"] = "transaction not found"
        return out

    msg = tx.get("transaction", {}).get("message", {})
    instrs = msg.get("instructions", []) or []
    for ix in instrs:
        prog_id = ix.get("programId", "")
        name, kind = KNOWN_PROGRAMS.get(prog_id, ("Unknown program", "unknown"))
        parsed_type = ""
        info = {}
        if isinstance(ix.get("parsed"), dict):
            parsed_type = ix["parsed"].get("type", "")
            info = ix["parsed"].get("info", {}) or {}
        out["instructions"].append({
            "program": name, "programId": prog_id, "kind": kind,
            "type": parsed_type, "info": info,
        })
        if kind == "unknown":
            out["flags"].append({
                "severity": "caution",
                "text": f"Unknown program invoked: {prog_id[:12]}… — verify it before signing.",
            })
        if parsed_type in ("approve", "approveChecked"):
            amt = info.get("amount") or info.get("tokenAmount", {}).get("amount")
            out["flags"].append({
                "severity": "high",
                "text": f"Token APPROVAL detected (delegate {str(info.get('delegate'))[:8]}…) — "
                        f"common drainer pattern. Delegate can move your tokens.",
            })
        if parsed_type == "setAuthority":
            out["flags"].append({
                "severity": "high",
                "text": f"Authority CHANGE detected ({info.get('authorityType')}).",
            })

    meta = tx.get("meta", {}) or {}
    out["info"] = {
        "slot": tx.get("slot"),
        "fee_lamports": meta.get("fee"),
        "status": "success" if meta.get("err") is None else "failed",
        "accounts": len(msg.get("accountKeys", []) or []),
    }
    sev = [f["severity"] for f in out["flags"]]
    if "high" in sev:
        out["verdict"] = "HIGH_RISK"
    elif out["flags"]:
        out["verdict"] = "CAUTION"
    else:
        out["verdict"] = "NO_HARD_FLAGS"
    return out


def analyze_wallet(address: str) -> dict:
    out = {"address": address, "flags": [], "verdict": "UNKNOWN", "info": {}}
    try:
        bal = rpc("getBalance", [address])
        out["info"]["sol_balance"] = round((bal or {}).get("value", 0) / 1e9, 6)
        accs = rpc("getTokenAccountsByOwner", [address, {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                                                {"encoding": "jsonParsed"}])
        tokens = []
        for a in (accs or {}).get("value", []) or []:
            info = a.get("account", {}).get("data", {}).get("parsed", {}).get("info", {})
            amt = info.get("tokenAmount", {})
            if amt.get("uiAmount"):
                tokens.append({"mint": info.get("mint"), "amount": amt.get("uiAmountString")})
        out["info"]["token_accounts"] = len(tokens)
        out["info"]["tokens"] = tokens[:20]
    except Exception as exc:
        out["error"] = str(exc)
    out["verdict"] = "NO_HARD_FLAGS" if "error" not in out else "UNKNOWN"
    return out


class Handler(BaseHTTPRequestHandler):
    static_dir = Path(__file__).resolve().parent

    def log_message(self, *a):  # quiet
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, ctype: str):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = self.path.split("?")[0]
        try:
            if route == "/api/health":
                return self._json({"ok": True, "service": "solguard", "rpc": RPC})
            if route.startswith("/api/token/"):
                mint = route.rsplit("/", 1)[-1]
                if not is_base58(mint):
                    return self._json({"error": "invalid mint address"}, 400)
                return self._json(analyze_token(mint))
            if route.startswith("/api/tx/"):
                sig = route.rsplit("/", 1)[-1]
                if not is_base58(sig, 80, 90):
                    return self._json({"error": "invalid transaction signature"}, 400)
                return self._json(analyze_tx(sig))
            if route.startswith("/api/wallet/"):
                addr = route.rsplit("/", 1)[-1]
                if not is_base58(addr):
                    return self._json({"error": "invalid wallet address"}, 400)
                return self._json(analyze_wallet(addr))
            # static
            if route in ("/", "/index.html"):
                return self._file(self.static_dir / "index.html", "text/html; charset=utf-8")
            if route == "/styles.css":
                return self._file(self.static_dir / "styles.css", "text/css; charset=utf-8")
            if route == "/app.js":
                return self._file(self.static_dir / "app.js", "application/javascript; charset=utf-8")
            self._json({"error": "not found"}, 404)
        except Exception as exc:
            self._json({"error": str(exc)}, 500)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"SolGuard listening on http://0.0.0.0:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
