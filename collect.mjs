// Collects every service-fee payment into the fee wallet and writes the
// encrypted database the dashboard reads.
//
//   DASH_PASSWORD=... FEE_WALLET=0x... node collect.mjs
//
// Sources, no API keys needed:
//   - the explorer's token transfers into the fee wallet (Robinhood Chain
//     Blockscout, v2 API), newest first, read back until known ground;
//   - the chain RPC for each paying transaction: who sent it, and its calldata.
//
// A fee arrives as a TAKE from the Uniswap V4 PoolManager inside the user's own
// PositionManager transaction, so the transaction's sender is the contributor.
// One USDG TAKE can carry both kinds of fee (a re-entry pays 1.5% of the LP
// fees collected plus 0.3 USDG for the re-open), so it is split by decoding the
// transaction: 0.3 USDG per distinct pool it mints into (one ladder per pool),
// and the rest is the 1.5% share. Non-USDG TAKEs are the in-kind fallback of
// the 1.5% share. Transfers from anywhere else (airdrops, spam) are kept apart
// and never counted as revenue.
import fs from "node:fs";
import { seal, open } from "./vault.mjs";

const PASSWORD = process.env.DASH_PASSWORD;
const WALLET = String(process.env.FEE_WALLET || "").toLowerCase();
if (!PASSWORD || !/^0x[0-9a-f]{40}$/.test(WALLET)) {
  console.error("DASH_PASSWORD and FEE_WALLET are required");
  process.exit(2);
}
const DB_FILE = new URL("./data/db.enc", import.meta.url);

const EXPLORER = "https://robinhoodchain.blockscout.com";
const RPCS = process.env.RPCS ? process.env.RPCS.split(",") : ["https://rpc.mainnet.chain.robinhood.com", "https://robinhood-rpc.publicnode.com"];
const POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
const POSITION_MANAGER = "0x58daec3116aae6d93017baaea7749052e8a04fa7";
const USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
const OPEN_FEE_RAW = 300000n;            // 0.3 USDG, 6 decimals
const FEE_SHARE = 0.015;                 // 1.5% of the LP fees collected
const MODIFY_LIQUIDITIES = "0xdd46508f"; // modifyLiquidities(bytes,uint256)
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function withRetry(what, fn, tries = 8) {
  let last;
  for (let i = 0; i < tries; i++) {
    if (i) await sleep(Math.min(20000, 1000 * 2 ** i));
    try { return await fn(); } catch (e) { last = e; console.log(`  ${what} retry ${i + 1}: ${e.message}`); }
  }
  throw new Error(`${what}: ${last && last.message}`);
}

async function explorerPage(params) {
  const q = new URLSearchParams(params).toString();
  const url = `${EXPLORER}/api/v2/addresses/${WALLET}/token-transfers${q ? "?" + q : ""}`;
  return withRetry("explorer", async () => {
    const r = await fetch(url, { headers: { "User-Agent": UA, "Accept": "application/json" } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (!Array.isArray(j.items)) throw new Error("no items");
    return j;
  });
}

let rpcTurn = 0;
async function rpc(method, params) {
  return withRetry(method, async () => {
    const url = RPCS[rpcTurn++ % RPCS.length];
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    const j = await r.json();
    if (j.error) throw new Error(j.error.message);
    if (j.result == null) throw new Error("empty result");
    return j.result;
  });
}

// --- calldata: modifyLiquidities(abi.encode(bytes actions, bytes[] params), deadline)
const word = (hex, i) => hex.slice(i * 64, i * 64 + 64);
const num = (hex, i) => Number(BigInt("0x" + word(hex, i)));
function bytesAt(hex, offBytes) {           // dynamic `bytes` at a byte offset
  const len = Number(BigInt("0x" + hex.slice(offBytes * 2, offBytes * 2 + 64)));
  return hex.slice(offBytes * 2 + 64, offBytes * 2 + 64 + len * 2);
}
// Distinct pools minted into (MINT_POSITION 0x02, MINT_POSITION_FROM_DELTAS
// 0x05). A PoolKey is a static tuple, so it is the first five words of the
// action's params. Returns null when the calldata is not a direct
// modifyLiquidities call it can read.
function mintedPools(input) {
  try {
    if (!input || !input.toLowerCase().startsWith(MODIFY_LIQUIDITIES)) return null;
    const args = input.slice(10);
    const unlock = bytesAt(args, num(args, 0));
    const actions = bytesAt(unlock, num(unlock, 0));
    const pOff = num(unlock, 1) * 2;
    const arr = unlock.slice(pOff);
    const n = num(arr, 0);
    const pools = new Set();
    for (let i = 0; i < n; i++) {
      const code = parseInt(actions.slice(i * 2, i * 2 + 2), 16);
      if (code !== 0x02 && code !== 0x05) continue;
      const elOff = num(arr, 1 + i);                       // relative to the array's data
      const p = bytesAt(arr.slice(64), elOff);
      pools.add([0, 1, 2, 3, 4].map(k => word(p, k)).join(""));
    }
    return pools.size;
  } catch (e) { return null; }
}

// --- state
let db = { v: 1, wallet: WALLET, lastBlock: 0, transfers: {}, txs: {}, updatedAt: null };
if (fs.existsSync(DB_FILE)) {
  const prev = await open(fs.readFileSync(DB_FILE, "utf8"), PASSWORD);
  if (prev.wallet === WALLET) db = { ...db, ...prev };
}

// --- 1. new transfers, newest first, until a page reaches known ground
let params = {}, pages = 0, fresh = 0;
const stopAt = Math.max(0, db.lastBlock - 50);
for (;;) {
  const page = await explorerPage(params);
  pages++;
  if (pages % 5 === 0) console.log(`page ${pages}: ${fresh} new, at block ${page.items.length ? page.items[page.items.length - 1].block_number : "-"}`);
  for (const it of page.items) {
    if (String(it.to && it.to.hash).toLowerCase() !== WALLET) continue;
    const key = `${it.transaction_hash}:${it.log_index}`;
    if (db.transfers[key]) continue;
    const t = it.token || {}, total = it.total || {};
    db.transfers[key] = {
      b: Number(it.block_number), ts: it.timestamp, tx: it.transaction_hash.toLowerCase(),
      from: String(it.from && it.from.hash).toLowerCase(),
      token: String(t.address_hash || t.address || "").toLowerCase(), sym: t.symbol || "?",
      dec: Number(total.decimals != null ? total.decimals : t.decimals || 0), raw: String(total.value || "0"),
    };
    fresh++;
  }
  const oldest = page.items.length ? Number(page.items[page.items.length - 1].block_number) : 0;
  if (!page.next_page_params || oldest <= stopAt) break;
  params = page.next_page_params;
  await sleep(300);
}

// --- 2. each paying transaction once: sender and minted pools
const txHashes = [...new Set(Object.values(db.transfers).map(t => t.tx))].filter(h => !db.txs[h]);
for (const h of txHashes) {
  if (Object.keys(db.txs).length % 50 === 0) console.log(`txs ${Object.keys(db.txs).length}/${txHashes.length + Object.keys(db.txs).length}`);
  const tx = await rpc("eth_getTransactionByHash", [h]);
  db.txs[h] = {
    from: String(tx.from).toLowerCase(), to: String(tx.to || "").toLowerCase(),
    pools: mintedPools(tx.input),
  };
  await sleep(120);
}

// --- 3. one payment row per transaction
const byTx = new Map();
for (const t of Object.values(db.transfers)) {
  if (!byTx.has(t.tx)) byTx.set(t.tx, []);
  byTx.get(t.tx).push(t);
}
const payments = [], other = [];
for (const [h, list] of byTx) {
  const meta = db.txs[h] || {};
  const fee = list.filter(t => t.from === POOL_MANAGER);
  for (const t of list.filter(t => t.from !== POOL_MANAGER)) other.push({ ...t, sender: meta.from });
  if (!fee.length) continue;
  const usdgRaw = fee.filter(t => t.token === USDG).reduce((a, t) => a + BigInt(t.raw), 0n);
  let openRaw;
  if (meta.pools != null) {
    openRaw = BigInt(meta.pools) * OPEN_FEE_RAW;
    if (openRaw > usdgRaw) openRaw = usdgRaw;
  } else {
    // Unreadable calldata: whole multiples of 0.3 USDG are open fees.
    openRaw = usdgRaw > 0n && usdgRaw % OPEN_FEE_RAW === 0n ? usdgRaw : 0n;
  }
  const shareRaw = usdgRaw - openRaw;
  const inKind = fee.filter(t => t.token !== USDG)
    .map(t => ({ token: t.token, sym: t.sym, amount: Number(BigInt(t.raw)) / 10 ** t.dec }));
  const f = list[0];
  payments.push({
    tx: h, block: f.b, ts: f.ts, from: meta.from || "?",
    open: Number(openRaw) / 1e6, share: Number(shareRaw) / 1e6,
    // The 1.5% share implies the LP fees the user collected.
    lpFees: Number(shareRaw) / 1e6 / FEE_SHARE,
    opens: meta.pools == null ? null : meta.pools, decoded: meta.pools != null, inKind,
  });
}
payments.sort((a, b) => b.block - a.block);
db.lastBlock = Object.values(db.transfers).reduce((a, t) => Math.max(a, t.b), db.lastBlock);
db.updatedAt = new Date().toISOString();
db.payments = payments;
db.other = other.sort((a, b) => b.b - a.b).slice(0, 200);
db.feeShare = FEE_SHARE;
db.openFee = Number(OPEN_FEE_RAW) / 1e6;

fs.mkdirSync(new URL("./data/", import.meta.url), { recursive: true });
fs.writeFileSync(DB_FILE, await seal(db, PASSWORD));
const sum = k => payments.reduce((a, p) => a + p[k], 0);
console.log(`pages ${pages}, new transfers ${fresh}, new txs ${txHashes.length}, payments ${payments.length}`
  + `, revenue ${(sum("open") + sum("share")).toFixed(2)} USDG (open ${sum("open").toFixed(2)}, share ${sum("share").toFixed(2)})`
  + `, undecoded ${payments.filter(p => !p.decoded).length}, other ${other.length}`);
