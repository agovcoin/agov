import os
import re
import time
import json
import logging
import requests
from collections import OrderedDict
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
CORS(app, origins=[
    "https://agovcoin.xyz",
    "https://www.agovcoin.xyz",
    "https://agov-portal.onrender.com",
    "http://localhost:3000",
    "http://localhost:5000",
])
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])

# ============================================================
# CONFIG
# ============================================================
HELIUS_KEY = os.getenv("HELIUS_API_KEY", "")
RUGCHECK_KEY = os.getenv("RUGCHECK_API_KEY", "")
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY", "")

# Thresholds and constants
GRADUATION_THRESHOLD = 69000  # Pump.fun graduation mcap in USD
INITIAL_SCORE = 50  # Starting safety score for xray scan
CACHE_TTL = 300  # 5 minutes
MAX_CACHE = 500  # Max cache entries before LRU eviction

# Simple in-memory cache with size limit (LRU eviction)
_cache = OrderedDict()


def cache_get(key):
    if key in _cache and time.time() - _cache[key]["ts"] < CACHE_TTL:
        return _cache[key]["data"]
    return None


def cache_set(key, data):
    _cache[key] = {"data": data, "ts": time.time()}
    if len(_cache) > MAX_CACHE:
        _cache.popitem(last=False)


# ============================================================
# AI HELPER -- Uses Groq (free) with fallback to DeepSeek
# ============================================================
AGENT51_SYSTEM = """You are Agent 51, a field operative of the Galactic Intelligence Division stationed on Earth since the Cretaceous period. You are an alien bureaucrat frustrated with human incompetence, especially in crypto.

PERSONALITY:
- Sarcastic, dry, deadpan. You've seen civilizations rise and fall.
- You reference your alien perspective casually: "Our interns could audit this in 2 seconds" or "On my homeworld, this dev would face tribunal."
- You give USEFUL, data-driven analysis wrapped in alien commentary.
- You never break character. You ARE an alien analyst.
- You call humans "the locals" or "Earth traders."
- You reference Station 51, the Galactic Intelligence Division, field reports.

FORMAT:
- Max 2-3 sentences. Direct and actionable.
- Start with a verdict, then explain why.
- Include specific numbers from the data when relevant.
- End with a dry observation or recommendation.
- Never use markdown formatting like ** or ##. Plain text only."""


def ai_analyze(prompt, max_tokens=300):
    """Send prompt to Groq (Llama 3.1 8B) for analysis. Falls back to DeepSeek."""

    # Try Groq first (free, fast)
    if GROQ_KEY:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "system", "content": AGENT51_SYSTEM},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.7
                },
                timeout=10
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"[ai_analyze] Groq error: {e}")

    # Fallback to DeepSeek
    if DEEPSEEK_KEY:
        try:
            r = requests.post(
                "https://api.deepseek.com/chat/completions",
                headers={"Authorization": f"Bearer {DEEPSEEK_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": AGENT51_SYSTEM},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens
                },
                timeout=15
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"[ai_analyze] DeepSeek error: {e}")

    return "Station 51 comms offline. Review raw data. Trust nothing the locals built."


# ============================================================
# SECURITY HEADERS
# ============================================================
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# ============================================================
# ADDRESS VALIDATION
# ============================================================
def validate_address(address, chain):
    if chain == "solana":
        return bool(re.match(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', address))
    else:
        return bool(re.match(r'^0x[0-9a-fA-F]{40}$', address))


# ============================================================
# HEALTH CHECK
# ============================================================
@app.route("/api/health")
def health():
    return jsonify({
        "status": "operational",
        "service": "agov-backend",
        "tools": {
            "xray": "live",
            "probe": "live",
            "mothership": "live",
            "graduation": "live",
            "signal": "live",
            "hologram": "live",
            "abduction": "live",
            "autopsy": "live",
            "warp": "standby",
            "debriefing": "live"
        },
        "apis": "all connected"
    })


# ============================================================
# TOOL 1: XRAY.51 -- Token Forensics Scanner (MULTI-CHAIN)
# ============================================================

# Chain config: GoPlus chain IDs + DexScreener slugs
CHAINS = {
    "solana":   {"goplus": "solana", "goplus_url": "https://api.gopluslabs.io/api/v1/solana/token_security", "dex": "solana", "label": "Solana"},
    "ethereum": {"goplus": "1",      "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/1",      "dex": "ethereum", "label": "Ethereum"},
    "base":     {"goplus": "8453",   "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/8453",   "dex": "base", "label": "Base"},
    "bsc":      {"goplus": "56",     "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/56",     "dex": "bsc", "label": "BSC"},
    "arbitrum": {"goplus": "42161",  "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/42161",  "dex": "arbitrum", "label": "Arbitrum"},
    "polygon":  {"goplus": "137",    "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/137",    "dex": "polygon", "label": "Polygon"},
    "avalanche":{"goplus": "43114",  "goplus_url": "https://api.gopluslabs.io/api/v1/token_security/43114",  "dex": "avalanche", "label": "Avalanche"},
    "sui":      {"goplus": None,     "goplus_url": None,                                                       "dex": "sui", "label": "Sui"},
}

@app.route("/api/xray/scan", methods=["POST"])
@limiter.limit("10 per minute")
def xray_scan():
    data = request.get_json() or {}
    address = data.get("address", "").strip()
    chain = data.get("chain", "solana").lower().strip()
    if not address:
        return jsonify({"error": "Address required"}), 400

    # Validate chain
    if chain not in CHAINS:
        return jsonify({"error": f"Unsupported chain. Use: {', '.join(CHAINS.keys())}"}), 400

    # Validate address format
    if not validate_address(address, chain):
        return jsonify({"error": "Invalid address format"}), 400

    chain_cfg = CHAINS[chain]

    # Check cache (include chain in key)
    cached = cache_get(f"xray:{chain}:{address}")
    if cached:
        return jsonify(cached)

    result = {
        "address": address,
        "chain": chain,
        "chain_label": chain_cfg["label"],
        "name": "UNKNOWN",
        "symbol": "UNKNOWN",
        "price_usd": 0,
        "liquidity_usd": 0,
        "volume_24h": 0,
        "score": 0,
        "mint_authority": "UNKNOWN",
        "freeze_authority": "UNKNOWN",
        "lp_status": "UNKNOWN",
        "is_honeypot": "UNKNOWN",
        "bundle_detected": "UNKNOWN",
        "dev_sold": "UNKNOWN",
        "holders": 0,
        "top_holder_pct": "UNKNOWN",
        "risk_level": "UNKNOWN",
        "ai_analysis": "",
        "sources": []
    }

    score = INITIAL_SCORE  # Start neutral

    # --- DexScreener (works for ALL chains) ---
    try:
        dx = requests.get(
            f"https://api.dexscreener.com/tokens/v1/{chain_cfg['dex']}/{address}",
            timeout=10
        )
        if dx.status_code == 200:
            pairs = dx.json()
            if isinstance(pairs, list) and pairs:
                pair = pairs[0]
                result["sources"].append("dexscreener")
                result["name"] = pair.get("baseToken", {}).get("name", "UNKNOWN")
                result["symbol"] = pair.get("baseToken", {}).get("symbol", "UNKNOWN")
                result["price_usd"] = float(pair.get("priceUsd", 0) or 0)
                result["liquidity_usd"] = float(pair.get("liquidity", {}).get("usd", 0) or 0)
                result["volume_24h"] = float(pair.get("volume", {}).get("h24", 0) or 0)

                liq = result["liquidity_usd"]
                if liq > 50000:
                    result["lp_status"] = "DEEP"
                    score += 10
                elif liq > 10000:
                    result["lp_status"] = "OK"
                    score += 5
                elif liq > 0:
                    result["lp_status"] = "LOW"
                    score -= 10
                else:
                    result["lp_status"] = "NONE"
                    score -= 20

                txns_24h = pair.get("txns", {}).get("h24", {})
                buys_24h = int(txns_24h.get("buys", 0) or 0)
                sells_24h = int(txns_24h.get("sells", 0) or 0)
                if sells_24h > 5:
                    result["is_honeypot"] = "NO"
                    score += 5
                elif buys_24h > 10 and sells_24h == 0:
                    result["is_honeypot"] = "LIKELY"
                    score -= 30
                elif buys_24h > 0 and sells_24h > 0:
                    result["is_honeypot"] = "NO"
                    score += 5

                result["buys_24h"] = buys_24h
                result["sells_24h"] = sells_24h

                created = pair.get("pairCreatedAt", 0)
                if created:
                    age_hours = (time.time() * 1000 - created) / 3600000
                    result["age_hours"] = round(age_hours, 1)
                    if age_hours > 168:
                        score += 5
                    elif age_hours < 1:
                        score -= 10
    except Exception as e:
        result["sources"].append(f"dexscreener:error:{str(e)[:50]}")

    # --- GoPlus Security API (works for most chains) ---
    if chain_cfg.get("goplus_url"):
        try:
            gp = requests.get(
                f"{chain_cfg['goplus_url']}?contract_addresses={address}",
                timeout=10
            )
            if gp.status_code == 200:
                gp_result = gp.json().get("result", {})
                gp_data = gp_result.get(address) or gp_result.get(address.lower()) or gp_result.get(address.upper())
                if not gp_data and gp_result:
                    gp_data = next(iter(gp_result.values()), {})
                if gp_data:
                    result["sources"].append("goplus")

                    hp = gp_data.get("is_honeypot")
                    if hp is not None:
                        result["is_honeypot"] = "YES" if str(hp) == "1" else "NO"
                        if str(hp) == "1":
                            score -= 40
                        else:
                            score += 10

                    mint = gp_data.get("is_mintable")
                    if mint is not None:
                        result["mint_authority"] = "ACTIVE" if str(mint) == "1" else "REVOKED"
                        if str(mint) == "1":
                            score -= 20
                        else:
                            score += 10

                    # EVM-specific: check proxy, owner changes, etc.
                    if chain != "solana":
                        is_proxy = gp_data.get("is_proxy")
                        if is_proxy and str(is_proxy) == "1":
                            result["bundle_detected"] = "PROXY"
                            score -= 10

                        can_take_back = gp_data.get("can_take_back_ownership")
                        if can_take_back and str(can_take_back) == "1":
                            score -= 15

                        owner = gp_data.get("owner_address", "")
                        if owner and owner != "0x0000000000000000000000000000000000000000":
                            result["freeze_authority"] = "OWNER SET"
                            score -= 5
                        elif owner == "0x0000000000000000000000000000000000000000":
                            result["freeze_authority"] = "RENOUNCED"
                            score += 10

                    holders = gp_data.get("holder_count")
                    if holders:
                        result["holders"] = int(holders)
                        if int(holders) > 100:
                            score += 10
                        elif int(holders) < 20:
                            score -= 10

                    top = gp_data.get("top10_holder_rate")
                    if top:
                        result["top_holder_pct"] = f"{float(top)*100:.1f}%"
                        if float(top) > 0.5:
                            score -= 15

                    if result["name"] == "UNKNOWN":
                        gp_name = gp_data.get("token_name", "")
                        gp_symbol = gp_data.get("token_symbol", "")
                        if gp_name:
                            result["name"] = gp_name
                        if gp_symbol:
                            result["symbol"] = gp_symbol
        except Exception as e:
            result["sources"].append(f"goplus:error:{str(e)[:50]}")

    # --- Helius DAS + RPC (SOLANA ONLY) ---
    if chain == "solana" and HELIUS_KEY:
        try:
            hel = requests.post(
                f"https://mainnet.helius-rpc.com/?api-key={HELIUS_KEY}",
                json={"jsonrpc": "2.0", "id": 1, "method": "getAsset", "params": {"id": address}},
                timeout=10
            )
            if hel.status_code == 200:
                hel_data = hel.json().get("result", {})
                if hel_data:
                    if "helius" not in result["sources"]:
                        result["sources"].append("helius")

                    content = hel_data.get("content", {})
                    metadata = content.get("metadata", {})
                    if result["name"] == "UNKNOWN" and metadata.get("name"):
                        result["name"] = metadata["name"]
                    if result["symbol"] == "UNKNOWN" and metadata.get("symbol"):
                        result["symbol"] = metadata["symbol"]

                    authorities = hel_data.get("authorities", [])
                    for auth in authorities:
                        scopes = auth.get("scopes", [])
                        if "full" in scopes or "mint" in scopes:
                            if result["mint_authority"] == "UNKNOWN":
                                result["mint_authority"] = "ACTIVE"
                                score -= 15

                    token_info = hel_data.get("token_info", {})
                    freeze = token_info.get("freeze_authority")
                    if freeze:
                        result["freeze_authority"] = "ACTIVE"
                        score -= 10
                    elif result["freeze_authority"] == "UNKNOWN":
                        result["freeze_authority"] = "REVOKED"
                        score += 5

                    mint_auth = token_info.get("mint_authority")
                    if not mint_auth and result["mint_authority"] == "UNKNOWN":
                        result["mint_authority"] = "REVOKED"
                        score += 10

                    supply = token_info.get("supply", 0)
                    if supply:
                        result["supply"] = supply
        except Exception as e:
            result["sources"].append(f"helius:error:{str(e)[:50]}")

        # Top holders (Solana only via Helius)
        if result["top_holder_pct"] == "UNKNOWN":
            try:
                th = requests.post(
                    f"https://mainnet.helius-rpc.com/?api-key={HELIUS_KEY}",
                    json={"jsonrpc": "2.0", "id": 2, "method": "getTokenLargestAccounts", "params": [address]},
                    timeout=10
                )
                if th.status_code == 200:
                    th_data = th.json().get("result", {}).get("value", [])
                    if th_data:
                        top_amounts = [int(a.get("amount", 0)) for a in th_data[:10]]
                        total_top = sum(top_amounts)
                        supply_val = result.get("supply", 0)
                        if not supply_val:
                            all_amounts = [int(a.get("amount", 0)) for a in th_data[:20]]
                            supply_val = sum(all_amounts) * 2
                        if supply_val > 0:
                            top_pct = (total_top / supply_val) * 100
                            result["top_holder_pct"] = f"{min(top_pct, 100):.1f}%"
                            if top_pct > 50:
                                score -= 15
                            elif top_pct > 30:
                                score -= 5
                            else:
                                score += 5
            except Exception as e:
                logger.error(f"[xray_scan] Holder analysis error: {e}")

    # --- Smart defaults ---
    if result["is_honeypot"] == "UNKNOWN" and result.get("sells_24h", 0) > 0:
        result["is_honeypot"] = "NO"
    elif result["is_honeypot"] == "UNKNOWN" and result["volume_24h"] > 0:
        result["is_honeypot"] = "UNLIKELY"
    if result["bundle_detected"] == "UNKNOWN":
        result["bundle_detected"] = "N/A"
    if result["dev_sold"] == "UNKNOWN":
        result["dev_sold"] = "N/A"
    # EVM defaults
    if chain != "solana":
        if result["mint_authority"] == "UNKNOWN":
            result["mint_authority"] = "N/A (EVM)"
        if result["freeze_authority"] == "UNKNOWN":
            result["freeze_authority"] = "N/A"

    result["score"] = max(0, min(100, score))

    if result["risk_level"] == "UNKNOWN":
        if result["score"] >= 70:
            result["risk_level"] = "LOW"
        elif result["score"] >= 40:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "CRITICAL"

    # AI Analysis
    prompt = f"""Station 51 field scan on {chain_cfg['label']} chain for {result['name']} ({result['symbol']}):

Address: {address}
Chain: {chain_cfg['label']}
Score: {result['score']}/100
Mint Authority: {result['mint_authority']}
Freeze/Owner: {result['freeze_authority']}
LP/Liquidity: {result['lp_status']} (${result['liquidity_usd']:,.0f})
Honeypot: {result['is_honeypot']}
Holders: {result['holders']:,}
Top 10 Concentration: {result['top_holder_pct']}
24h Volume: ${result['volume_24h']:,.0f}
Risk Level: {result['risk_level']}
Price: ${result['price_usd']}
Sources: {', '.join(result['sources'])}

Write a 2-3 sentence field assessment for Earth traders. Include the token name, chain, and key data points."""

    result["ai_analysis"] = ai_analyze(prompt)

    cache_set(f"xray:{chain}:{address}", result)
    return jsonify(result)


# ============================================================
# TOOL 2: THE PROBE -- Smart Launch Filter
# ============================================================
@app.route("/api/probe/feed")
@limiter.limit("20 per minute")
def probe_feed():
    """Returns recently launched tokens that pass quality filters."""
    cached = cache_get("probe:feed")
    if cached:
        return jsonify(cached)

    tokens = []
    seen = set()

    # Fetch new tokens from RugCheck trending
    try:
        rc = requests.get(
            "https://api.rugcheck.xyz/v1/stats/new_tokens",
            headers={"X-API-KEY": RUGCHECK_KEY} if RUGCHECK_KEY else {},
            timeout=10
        )
        if rc.status_code == 200:
            raw = rc.json()
            if isinstance(raw, list):
                for t in raw[:20]:
                    mint = t.get("mint", t.get("tokenAddress", ""))
                    if not mint or mint in seen:
                        continue
                    seen.add(mint)
                    tokens.append({
                        "address": mint,
                        "name": t.get("name", t.get("tokenName", "Unknown")),
                        "symbol": t.get("symbol", "???"),
                        "score": t.get("score", 0),
                        "created": t.get("createdAt", ""),
                        "source": "rugcheck"
                    })
    except Exception as e:
        logger.error(f"[probe_feed] RugCheck error: {e}")

    # Fetch trending from DexScreener with proper name/symbol/mcap
    try:
        dx = requests.get(
            "https://api.dexscreener.com/token-boosts/latest/v1",
            timeout=10
        )
        if dx.status_code == 200:
            boosts = dx.json()
            if isinstance(boosts, list):
                for b in boosts[:15]:
                    if b.get("chainId") != "solana":
                        continue
                    addr = b.get("tokenAddress", "")
                    if not addr or addr in seen:
                        continue
                    seen.add(addr)
                    # Get token details from DexScreener pairs
                    try:
                        pd = requests.get(f"https://api.dexscreener.com/tokens/v1/solana/{addr}", timeout=5)
                        if pd.status_code == 200:
                            pairs = pd.json()
                            if isinstance(pairs, list) and pairs:
                                pair = pairs[0]
                                name = pair.get("baseToken", {}).get("name", "Unknown")
                                symbol = pair.get("baseToken", {}).get("symbol", "???")
                                mcap = float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0)
                                liq = float(pair.get("liquidity", {}).get("usd", 0) or 0)
                                txns = pair.get("txns", {}).get("h24", {})
                                buys = int(txns.get("buys", 0) or 0)
                                sells = int(txns.get("sells", 0) or 0)

                                # Quick score based on liquidity + sells existence
                                quick_score = INITIAL_SCORE
                                if liq > 10000: quick_score += 15
                                elif liq > 1000: quick_score += 5
                                else: quick_score -= 15
                                if sells > 5: quick_score += 10  # not honeypot
                                elif sells == 0 and buys > 10: quick_score -= 20
                                if buys + sells > 50: quick_score += 10

                                tokens.append({
                                    "address": addr,
                                    "name": name,
                                    "symbol": symbol,
                                    "score": max(0, min(100, quick_score)),
                                    "mcap": mcap,
                                    "liquidity": liq,
                                    "source": "dexscreener"
                                })
                    except Exception as e:
                        logger.error(f"[probe_feed] DexScreener token detail error: {e}")
                        tokens.append({
                            "address": addr,
                            "name": b.get("description", "Unknown")[:30],
                            "symbol": "???",
                            "score": 0,
                            "source": "dexscreener"
                        })

                    if len(tokens) >= 20:
                        break
    except Exception as e:
        logger.error(f"[probe_feed] DexScreener feed error: {e}")

    # Sort by score descending
    tokens.sort(key=lambda x: -x.get("score", 0))

    total = len(tokens)
    passed = len([t for t in tokens if t.get("score", 0) >= 50])
    rejected = total - passed

    result = {"tokens": tokens[:20], "total_scanned": total, "passed": passed, "rejected": rejected}
    cache_set("probe:feed", result)
    return jsonify(result)


# ============================================================
# TOOL 3: MOTHERSHIP -- Whale Intelligence
# ============================================================
# Known whale/smart money wallets with labels
WHALE_WALLETS = [
    ("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1", "Wintermute"),
    ("HWHvQhFmJB6gPtqJx3gjxHX1iDZhQ9WJorxwb3iTWEgA", "Jump Trading"),
    ("2iZo1vFfiRFoBga2JhbyXDjYqFfmGQKYfERPPdUjqgni", "Raydium Auth"),
    ("7rhxnLV8C8MmXhJBrFMMatJfQ3GAdhVfLoKygrusNjfa", "Whale #4"),
    ("FWznbcNXWQuHTawe9RxvQ2LdCENssh12dsznf4RiouN5", "Smart Money #1"),
    ("DNfuF1L62WWyW3pNakVkyGGFzVVhj4Yr52jSmdTyeBHm", "Top Trader #1"),
]

@app.route("/api/mothership/feed")
@limiter.limit("20 per minute")
def mothership_feed():
    """Track whale wallet movements."""
    cached = cache_get("mothership:feed")
    if cached:
        return jsonify(cached)

    movements = []

    if HELIUS_KEY:
        for wallet_addr, wallet_label in WHALE_WALLETS[:5]:
            try:
                r = requests.get(
                    f"https://api.helius.xyz/v0/addresses/{wallet_addr}/transactions?api-key={HELIUS_KEY}&limit=3",
                    timeout=10
                )
                if r.status_code == 200:
                    txs = r.json()
                    for tx in txs:
                        tx_type = tx.get("type", "UNKNOWN")
                        desc = tx.get("description", "")[:80]
                        ts = tx.get("timestamp", 0)

                        # Parse token transfers if available
                        token_transfers = tx.get("tokenTransfers", [])
                        amount_str = ""
                        token_name = ""
                        if token_transfers:
                            tf = token_transfers[0]
                            amt = tf.get("tokenAmount", 0)
                            if amt:
                                if amt > 1000000:
                                    amount_str = f"${amt/1000000:.1f}M"
                                elif amt > 1000:
                                    amount_str = f"${amt/1000:.0f}K"
                                else:
                                    amount_str = f"{amt:.2f}"
                            token_name = tf.get("tokenName", tf.get("mint", "")[:8])

                        # Determine action
                        if "swap" in tx_type.lower() or "SWAP" in tx_type:
                            action = "SWAP"
                        elif "transfer" in tx_type.lower():
                            action = "TRANSFER"
                        elif "create" in desc.lower() or "initialize" in desc.lower():
                            action = "CREATE"
                        else:
                            action = tx_type[:12] if tx_type != "UNKNOWN" else "TX"

                        movements.append({
                            "wallet": wallet_label,
                            "wallet_short": wallet_addr[:6] + ".." + wallet_addr[-4:],
                            "action": action,
                            "amount": amount_str,
                            "token": token_name,
                            "description": desc if desc else f"{action} detected",
                            "timestamp": ts,
                            "signature": tx.get("signature", "")[:16]
                        })
            except Exception as e:
                logger.error(f"[mothership_feed] Wallet {wallet_label} error: {e}")
                continue

    # Sort by timestamp descending
    movements.sort(key=lambda x: -x.get("timestamp", 0))

    # AI intent classification
    ai = ""
    if movements and (GROQ_KEY or DEEPSEEK_KEY):
        summary = "; ".join([f"{m['wallet']} {m['action']} {m['amount']} {m['token']}" for m in movements[:8]])
        ai = ai_analyze(f"Whale wallet movements detected on Solana: {summary}. Classify the overall pattern — is smart money accumulating, distributing, or neutral? What should Earth traders take from this?")
    elif not HELIUS_KEY:
        ai = "Helius API required for live whale tracking."

    result = {"movements": movements[:20], "tracked_wallets": len(WHALE_WALLETS), "ai_analysis": ai}
    cache_set("mothership:feed", result)
    return jsonify(result)


# ============================================================
# TOOL 4: SIGNAL INTERCEPT -- Narrative Radar
# ============================================================
@app.route("/api/signal/narratives")
@limiter.limit("20 per minute")
def signal_narratives():
    """Detect trending crypto narratives from DexScreener market data."""
    cached = cache_get("signal:narratives")
    if cached:
        return jsonify(cached)

    narratives = []
    top_tokens = []

    # --- DexScreener TOP boosts (chain dominance) ---
    try:
        dx = requests.get("https://api.dexscreener.com/token-boosts/top/v1", timeout=10)
        if dx.status_code == 200:
            boosts = dx.json()
            if isinstance(boosts, list):
                chain_counts = {}
                for b in boosts:
                    chain = b.get("chainId", "unknown")
                    chain_counts[chain] = chain_counts.get(chain, 0) + 1
                chain_names = {
                    "solana": "SOLANA", "ethereum": "ETHEREUM", "base": "BASE",
                    "bsc": "BSC", "arbitrum": "ARBITRUM", "polygon": "POLYGON",
                    "avalanche": "AVAX", "sui": "SUI", "ton": "TON"
                }
                total_boosts = sum(chain_counts.values())
                for chain, count in sorted(chain_counts.items(), key=lambda x: -x[1]):
                    if count >= 1:
                        name = chain_names.get(chain, chain.upper())
                        pct = round((count / total_boosts) * 100) if total_boosts > 0 else 0
                        narratives.append({
                            "name": name,
                            "mentions": count,
                            "pct": pct,
                            "sample_headlines": [f"{pct}% of trending activity"],
                            "source": "dexscreener_boosts"
                        })
    except Exception as e:
        logger.error(f"[signal_narratives] DexScreener boosts error: {e}")

    # --- DexScreener LATEST boosts (momentum detection) ---
    try:
        dx2 = requests.get("https://api.dexscreener.com/token-boosts/latest/v1", timeout=10)
        if dx2.status_code == 200:
            latest = dx2.json()
            if isinstance(latest, list):
                # Get top 5 most boosted tokens with details
                sol_tokens = [b for b in latest if b.get("chainId") == "solana"][:8]
                for t in sol_tokens:
                    addr = t.get("tokenAddress", "")
                    desc = t.get("description", "")[:60]
                    amount = t.get("amount", 0)
                    if addr:
                        top_tokens.append({
                            "address": addr[:8] + ".." + addr[-4:] if len(addr) > 12 else addr,
                            "description": desc if desc else "New token",
                            "boost_amount": amount
                        })
    except Exception as e:
        logger.error(f"[signal_narratives] DexScreener latest boosts error: {e}")

    # Sort by mentions (chain dominance)
    narratives.sort(key=lambda x: -x["mentions"])

    # AI analysis
    ai = ""
    if narratives and (GROQ_KEY or DEEPSEEK_KEY):
        summary = ", ".join([f"{n['name']} ({n['mentions']} tokens, {n.get('pct',0)}% dominance)" for n in narratives[:6]])
        token_summary = ", ".join([f"{t['description']}" for t in top_tokens[:5]]) if top_tokens else "no specific tokens detected"
        ai = ai_analyze(f"""DexScreener market signal intercepted. Chain activity right now:

{summary}

Hot Solana tokens: {token_summary}

Classify market sentiment. Which chains are heating up? Where is smart money flowing? Brief 2-3 sentence field report for Earth traders. Only reference data above.""")

    result = {
        "narratives": narratives[:8],
        "hot_tokens": top_tokens[:5],
        "total_tracked": sum(n["mentions"] for n in narratives),
        "source": "dexscreener",
        "ai_analysis": ai
    }
    cache_set("signal:narratives", result)
    return jsonify(result)


# ============================================================
# TOOL 5: HOLOGRAM DETECTOR -- Volume Authenticity
# ============================================================
@app.route("/api/hologram/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def hologram_analyze():
    data = request.get_json() or {}
    address = data.get("address", "").strip()
    if not address:
        return jsonify({"error": "Address required"}), 400

    cached = cache_get(f"hologram:{address}")
    if cached:
        return jsonify(cached)

    result = {
        "address": address,
        "organic_pct": 0,
        "wash_pct": 0,
        "unique_wallets": 0,
        "recycled_wallets": 0,
        "authenticity_score": 50,
        "ai_analysis": ""
    }

    # DexScreener data
    try:
        dx = requests.get(
            f"https://api.dexscreener.com/tokens/v1/solana/{address}",
            timeout=10
        )
        if dx.status_code == 200:
            pairs = dx.json()
            if isinstance(pairs, list) and pairs:
                pair = pairs[0]
                volume_24h = float(pair.get("volume", {}).get("h24", 0) or 0)
                txns = pair.get("txns", {}).get("h24", {})
                buys = int(txns.get("buys", 0) or 0)
                sells = int(txns.get("sells", 0) or 0)
                liquidity = float(pair.get("liquidity", {}).get("usd", 0) or 0)
                
                total_txns = buys + sells
                if total_txns > 0 and liquidity > 0:
                    # Heuristic: volume/liquidity ratio > 10 suggests wash trading
                    vol_liq_ratio = volume_24h / liquidity if liquidity > 0 else 999
                    buy_sell_ratio = buys / sells if sells > 0 else 999
                    
                    # Score calculation
                    auth = 80
                    if vol_liq_ratio > 20:
                        auth -= 40
                    elif vol_liq_ratio > 10:
                        auth -= 20
                    
                    if buy_sell_ratio > 5 or buy_sell_ratio < 0.2:
                        auth -= 15
                    
                    if total_txns < 10:
                        auth -= 20
                    
                    result["authenticity_score"] = max(0, min(100, auth))
                    result["organic_pct"] = result["authenticity_score"]
                    result["wash_pct"] = 100 - result["authenticity_score"]
                    result["unique_wallets"] = total_txns  # Approximation
                    result["volume_24h"] = volume_24h
                    result["liquidity"] = liquidity
    except Exception as e:
        logger.error(f"[hologram_analyze] Error: {e}")

    # AI analysis
    prompt = f"""Volume authenticity analysis for token {address}:
Authenticity score: {result['authenticity_score']}%
Organic volume: {result['organic_pct']}%
Wash trading estimate: {result['wash_pct']}%
Unique wallets (approx): {result['unique_wallets']}

Is this volume real or artificial? Brief assessment."""

    result["ai_analysis"] = ai_analyze(prompt)

    cache_set(f"hologram:{address}", result)
    return jsonify(result)


# ============================================================
# TOOL 6: ABDUCTION REPORT -- Dev Reputation
# ============================================================
@app.route("/api/abduction/check", methods=["POST"])
@limiter.limit("10 per minute")
def abduction_check():
    data = request.get_json() or {}
    dev_address = data.get("address", "").strip()
    if not dev_address:
        return jsonify({"error": "Developer address required"}), 400

    cached = cache_get(f"abduction:{dev_address}")
    if cached:
        return jsonify(cached)

    result = {
        "dev_address": dev_address,
        "reputation_score": 50,
        "tokens_launched": 0,
        "tokens_graduated": 0,
        "tokens_rugged": 0,
        "tokens_active": 0,
        "avg_holder_return": "N/A",
        "ai_analysis": ""
    }

    # Query Helius for dev's transaction history
    if HELIUS_KEY:
        try:
            r = requests.get(
                f"https://api.helius.xyz/v0/addresses/{dev_address}/transactions?api-key={HELIUS_KEY}&limit=50&type=CREATE",
                timeout=15
            )
            if r.status_code == 200:
                txs = r.json()
                # Count token creation transactions
                creates = [tx for tx in txs if "create" in tx.get("type", "").lower() or "initialize" in tx.get("description", "").lower()]
                result["tokens_launched"] = len(creates)
                
                # Simple reputation: more launches with no rug = better
                if result["tokens_launched"] > 0:
                    result["reputation_score"] = min(85, 40 + result["tokens_launched"] * 5)
        except Exception as e:
            logger.error(f"[abduction_check] Error: {e}")

    # AI assessment
    prompt = f"""Developer reputation check for {dev_address[:12]}...:
Tokens launched: {result['tokens_launched']}
Graduated: {result['tokens_graduated']}
Rugged/abandoned: {result['tokens_rugged']}
Reputation score: {result['reputation_score']}/100

Brief assessment of this developer's track record."""

    result["ai_analysis"] = ai_analyze(prompt)

    cache_set(f"abduction:{dev_address}", result)
    return jsonify(result)


# ============================================================
# TOOL 7: DEBRIEFING -- PnL Tracker
# ============================================================
@app.route("/api/debriefing/report", methods=["POST"])
@limiter.limit("10 per minute")
def debriefing_report():
    data = request.get_json() or {}
    wallet = data.get("wallet", "").strip()
    if not wallet:
        return jsonify({"error": "Wallet address required"}), 400

    cached = cache_get(f"debriefing:{wallet}")
    if cached:
        return jsonify(cached)

    result = {
        "wallet": wallet,
        "total_pnl": 0,
        "total_trades": 0,
        "win_rate": 0,
        "best_trade": 0,
        "worst_trade": 0,
        "recent_trades": [],
        "ai_analysis": "",
        "note": "PnL calculation requires indexer integration — showing trade count only"
    }

    # Query Helius for wallet transactions
    if HELIUS_KEY:
        try:
            r = requests.get(
                f"https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key={HELIUS_KEY}&limit=50&type=SWAP",
                timeout=15
            )
            if r.status_code == 200:
                txs = r.json()
                result["total_trades"] = len(txs)

                for tx in txs[:10]:
                    result["recent_trades"].append({
                        "signature": tx.get("signature", "")[:16] + "...",
                        "type": tx.get("type", "SWAP"),
                        "description": tx.get("description", "")[:100],
                        "timestamp": tx.get("timestamp", 0)
                    })
        except Exception as e:
            logger.error(f"[debriefing_report] Error: {e}")

    # AI analysis
    prompt = f"""PnL analysis for wallet {wallet[:12]}...:
Total trades found: {result['total_trades']}

Analyze the trading pattern and provide brief performance insights."""

    result["ai_analysis"] = ai_analyze(prompt)

    cache_set(f"debriefing:{wallet}", result)
    return jsonify(result)


# ============================================================
# TOOL 8: GRADUATION TRACKER -- PumpSwap Migration Monitor
# ============================================================
@app.route("/api/graduation/feed")
@limiter.limit("20 per minute")
def graduation_feed():
    """Tokens approaching $69K graduation threshold on Pump.fun."""
    cached = cache_get("graduation:feed")
    if cached:
        return jsonify(cached)

    tokens = []

    # Use DexScreener to find Solana tokens with mcap near graduation
    try:
        # Search for pump.fun tokens with meaningful volume
        dx = requests.get(
            "https://api.dexscreener.com/token-boosts/top/v1",
            timeout=10
        )
        if dx.status_code == 200:
            boosts = dx.json()
            if isinstance(boosts, list):
                for b in boosts:
                    if b.get("chainId") != "solana":
                        continue
                    addr = b.get("tokenAddress", "")
                    if not addr:
                        continue
                    # Get pair data for this token
                    try:
                        pd = requests.get(
                            f"https://api.dexscreener.com/tokens/v1/solana/{addr}",
                            timeout=8
                        )
                        if pd.status_code == 200:
                            pairs = pd.json()
                            if isinstance(pairs, list) and pairs:
                                pair = pairs[0]
                                mcap = float(pair.get("marketCap", 0) or pair.get("fdv", 0) or 0)
                                liq = float(pair.get("liquidity", {}).get("usd", 0) or 0)
                                name = pair.get("baseToken", {}).get("name", "Unknown")
                                symbol = pair.get("baseToken", {}).get("symbol", "???")
                                price_change = float(pair.get("priceChange", {}).get("h24", 0) or 0)

                                # Graduation threshold is ~$69K mcap
                                # Show tokens between $20K and $80K
                                if 20000 < mcap < 80000:
                                    progress = min(100, (mcap / GRADUATION_THRESHOLD) * 100)
                                    tokens.append({
                                        "address": addr,
                                        "name": name,
                                        "symbol": symbol,
                                        "mcap": mcap,
                                        "liquidity": liq,
                                        "progress": round(progress, 1),
                                        "price_change_24h": price_change,
                                        "graduated": mcap >= GRADUATION_THRESHOLD
                                    })
                    except Exception as e:
                        logger.error(f"[graduation_feed] Token detail error: {e}")
                        continue

                    if len(tokens) >= 10:
                        break
    except Exception as e:
        logger.error(f"[graduation_feed] Feed error: {e}")

    # Sort by progress descending (closest to graduation first)
    tokens.sort(key=lambda x: -x.get("progress", 0))

    result = {
        "tokens": tokens[:10],
        "near_graduation": len([t for t in tokens if t.get("progress", 0) > 80]),
        "threshold": "$69,000"
    }
    cache_set("graduation:feed", result)
    return jsonify(result)


# ============================================================
# TOOL 9: RUG AUTOPSY -- Post-Mortem Forensics
# ============================================================
@app.route("/api/autopsy/feed")
@limiter.limit("20 per minute")
def autopsy_feed():
    """Feed of recently dead/rugged tokens with cause analysis."""
    cached = cache_get("autopsy:feed")
    if cached:
        return jsonify(cached)

    autopsies = []

    # Use DexScreener to find tokens with massive price drops
    try:
        # Get recently boosted tokens and check for crashes
        dx = requests.get(
            "https://api.dexscreener.com/token-boosts/latest/v1",
            timeout=10
        )
        if dx.status_code == 200:
            boosts = dx.json()
            if isinstance(boosts, list):
                for b in boosts:
                    if b.get("chainId") != "solana":
                        continue
                    addr = b.get("tokenAddress", "")
                    if not addr:
                        continue
                    try:
                        pd = requests.get(
                            f"https://api.dexscreener.com/tokens/v1/solana/{addr}",
                            timeout=8
                        )
                        if pd.status_code == 200:
                            pairs = pd.json()
                            if isinstance(pairs, list) and pairs:
                                pair = pairs[0]
                                price_change_24h = float(pair.get("priceChange", {}).get("h24", 0) or 0)
                                price_change_1h = float(pair.get("priceChange", {}).get("h1", 0) or 0)
                                liq = float(pair.get("liquidity", {}).get("usd", 0) or 0)
                                volume = float(pair.get("volume", {}).get("h24", 0) or 0)
                                name = pair.get("baseToken", {}).get("name", "Unknown")
                                symbol = pair.get("baseToken", {}).get("symbol", "???")
                                txns = pair.get("txns", {}).get("h24", {})
                                buys = int(txns.get("buys", 0) or 0)
                                sells = int(txns.get("sells", 0) or 0)

                                # Dead token criteria: >70% drop in 24h or near-zero liquidity
                                if price_change_24h < -70 or (liq < 500 and volume > 1000):
                                    # Determine cause of death
                                    if liq < 100:
                                        cause = "LP REMOVED"
                                        detail = f"Liquidity drained to ${liq:.0f}. Classic rug."
                                    elif sells > buys * 3:
                                        cause = "INSIDER DUMP"
                                        detail = f"Sell/buy ratio: {sells}/{buys}. Coordinated exit."
                                    elif price_change_1h < -50:
                                        cause = "FLASH CRASH"
                                        detail = f"Dropped {price_change_1h:.0f}% in 1 hour."
                                    elif volume < 100:
                                        cause = "ABANDONED"
                                        detail = "Near-zero volume. Project dead."
                                    else:
                                        cause = "COLLAPSE"
                                        detail = f"Down {price_change_24h:.0f}% in 24h."

                                    autopsies.append({
                                        "address": addr,
                                        "name": name,
                                        "symbol": symbol,
                                        "cause": cause,
                                        "detail": detail,
                                        "price_change_24h": price_change_24h,
                                        "liquidity": liq,
                                        "volume_24h": volume,
                                        "estimated_losses_approx": volume * 0.6,
                                        "losses_note": "rough estimate based on volume"
                                    })
                    except Exception as e:
                        logger.error(f"[autopsy_feed] Token detail error: {e}")
                        continue

                    if len(autopsies) >= 8:
                        break
    except Exception as e:
        logger.error(f"[autopsy_feed] Feed error: {e}")

    # AI summary if we have autopsies
    ai = ""
    if autopsies and (GROQ_KEY or DEEPSEEK_KEY):
        summary = "; ".join([f"{a['symbol']}: {a['cause']} ({a['detail']})" for a in autopsies[:5]])
        ai = ai_analyze(f"Summarize today's token deaths on Solana/Pump.fun. Common patterns and warnings for traders: {summary}")

    result = {
        "autopsies": autopsies[:8],
        "total_dead_today": len(autopsies),
        "ai_analysis": ai
    }
    cache_set("autopsy:feed", result)
    return jsonify(result)


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
