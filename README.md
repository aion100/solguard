# SolGuard — Solana Safety Scanner

**Know before you sign.** An open, read-only tool that explains the risks of a
token, transaction or wallet on Solana — before you approve anything.

Built for the **Superteam "Road to Colosseum" hackathon**.

## The problem
Drainers don't need your seed phrase. One malicious signature — a token
approval, an authority change — can empty a wallet. Most people sign without
understanding what a transaction actually does. There is no simple, readable
"what does this do and is it dangerous?" layer.

## The product
Paste a **token mint**, a **transaction signature**, or a **wallet address**
and get a plain-language risk report:

- **Token:** supply, mint/freeze authority status, known-token registry,
  market data (price, liquidity, FDV, 24h volume) with liquidity/volume flags.
- **Transaction:** every instruction with a known-program registry (Jupiter,
  Raydium, Orca, Pump.fun, SPL Token…), highlights unknown programs, detects
  dangerous patterns (`approve` → drainer, `setAuthority`).
- **Wallet:** SOL balance, token accounts, token list.

**Read-only.** No wallet connection, no signatures, no keys ever.

## Solana integration
- `getTokenSupply`, `getAccountInfo` (parsed) — authorities + supply.
- `getTransaction` (jsonParsed) — instruction-level analysis.
- `getBalance`, `getTokenAccountsByOwner` — wallet view.
- Program registry maps IDs to human names (DEXes, launchpads, core).
- Runs against **mainnet-beta** public RPC; works on devnet with one flag.

## Run locally
```bash
python3 server.py --port 8080
# open http://localhost:8080
```
No dependencies beyond the Python standard library.

## Architecture
- `server.py` — API (stdlib HTTP server) + analysis engine.
- `index.html` / `styles.css` / `app.js` — frontend (vanilla JS, no build step).
- `test/` — smoke tests.

## License
MIT.
