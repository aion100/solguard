# SolGuard — Solana Safety Scanner

**Know before you sign.** A read-only tool that shows what a Solana transaction
*actually does*, who loses what, and which approvals are quietly draining you.

- **Live:** https://solguard-aion-100pln.surge.sh
- **Demo video:** https://vimeo.com/1232663505
- **Network:** Solana **mainnet-beta** (read-only)

## The problem
Drainers don't need your seed phrase. One malicious signature — a token
approval, an authority change — can empty a wallet. People sign transactions
every day without any readable way to know what they are authorising.

## Three things SolGuard does

### 1. Token risk
Paste a mint: supply, mint/freeze authority, **Token-2022 extensions**
(transfer hooks, permanent delegates, default-frozen accounts), live market
data (price, liquidity, FDV, volume), pair age, and activity level.

### 2. Transaction autopsy
Paste any transaction signature and get a plain-language breakdown:
- **SOL movement** — every account that gained or lost SOL, signers marked
- **Token movement** — who sent what, with real amounts
- **Instruction list** — with a known-program registry (Jupiter, Raydium,
  Orca, Pump.fun, Meteora…) and unknown programs flagged
- **Dangerous patterns** — token approvals, authority changes
- **Execution logs** on demand

### 3. Wallet approval audit
Paste a wallet: SOL balance, all token holdings, and — most importantly —
**every active delegation**. A delegate can move your tokens without asking.
SolGuard surfaces them so you can revoke what you don't recognise.

**Read-only.** No wallet connection, no signatures, no keys. Ever.

## Solana integration
Live mainnet reads via public RPC:
`getAccountInfo` (parsed), `getTransaction` (jsonParsed, incl. pre/post
balances), `getBalance`, `getTokenAccountsByOwner`, `getSignaturesForAddress`.
Market data from the DexScreener public API. Endpoint fallback built in.

## Run locally
```bash
python3 server.py --port 8080   # optional self-hosted backend
# or just open index.html — the app is fully client-side
```
No dependencies for the frontend. The optional backend uses the Python
standard library only.

## Tests
```bash
python3 test/smoke.py
```

## License
MIT.
