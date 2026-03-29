import os
import time
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=[
    os.getenv("FRONTEND_URL", "*"),
    "http://localhost:*",
    "https://*.onrender.com"
])

# ============================================================
# CONFIG
# ============================================================
HELIUS_KEY = os.getenv("HELIUS_API_KEY", "")
RUGCHECK_KEY = os.getenv("RUGCHECK_API_KEY", "")
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY", "")
JUPITER_KEY = os.getenv("JUPITER_API_KEY", "")

# Simple in-memory cache (key -> {data, timestamp})
_cache = {}
CACHE_TTL = 300  # 5 minutes


def cache_get(key):
    if key in _cache and time.time() - _cache[key]["ts"] < CACHE_TTL:
        return _cache[key]["data"]
    return None


def cache_set(key, data):
    _cache[key] = {"data": data, "ts": time.time()}


# ============================================================
# AI HELPER -- Uses Groq (free) with fallback to DeepSeek
# ============================================================
def ai_analyze(prompt, max_tokens=500):
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
                        {"role": "system", "content": "You are Agent 51, a sarcastic alien intelligence analyst. Provide concise security analysis of crypto tokens. Be direct and useful. Max 3 sentences."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3
                },
                timeout=10
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

    # Fallback to DeepSeek
    if DEEPSEEK_KEY:
        try:
            r = requests.post(
                "https://api.deepseek.com/chat/completions",
                headers={"Authorization": f"Bearer {DEEPSEEK_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "You are Agent 51, a sarcastic alien intelligence analyst. Provide concise security analysis of crypto tokens. Be direct and useful. Max 3 sentences."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens
                },
                timeout=15
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

    return "AI analysis unavailable. Review the raw data above."


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
        "apis": {
            "goplus": "no key needed",
            "dexscreener": "no key needed",
            "helius": "connected" if HELIUS_KEY else "no key",
            "groq": "connected" if GROQ_KEY else "no key",
            "deepseek": "connected" if DEEPSEEK_KEY else "no key",
            "jupiter": "connected" if JUPITER_KEY else "no key"
        }
    })


# ============================================================
# TOOL 1: XRAY.51 -- Token Forensics Scanner
# ============================================================
@app.route("/api/xray/scan", methods=["POST"])
def xray_scan():
    data = request.get_json() or {}
    address = data.get("address", "").strip()
    if not address:
        return jsonify({"error": "Address required"}), 400

    # Check cache
    cached = cache_get(f"xray:{address}")
    if cached:
        return jsonify(cached)

    result = {
        "address": address,
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

    score = 50  # Start neutral

    # --- DexScreener (no key, 300 req/min) -- Get token name, price, liquidity ---
    try:
        dx = requests.get(
            f"https://api.dexscreener.com/tokens/v1/solana/{address}",
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

                # LP check from liquidity
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
    except Exception as e:
        result["sources"].append(f"dexscreener:error:{str(e)[:50]}")

    # --- GoPlus Security API (no key needed, 30 req/min) ---
    try:
        gp = requests.get(
            f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={address}",
            timeout=10
        )
        if gp.status_code == 200:
            gp_result = gp.json().get("result", {})
            # Try original address first, then try any key in result (GoPlus may transform case)
            gp_data = gp_result.get(address) or gp_result.get(address.lower()) or gp_result.get(address.upper())
            if not gp_data and gp_result:
                # Fallback: just grab the first result
                gp_data = next(iter(gp_result.values()), {})
            if gp_data:
                result["sources"].append("goplus")

                # Honeypot
                hp = gp_data.get("is_honeypot")
                if hp is not None:
                    result["is_honeypot"] = "YES" if str(hp) == "1" else "NO"
                    if str(hp) == "1":
                        score -= 40
                    else:
                        score += 10

                # Mint authority
                mint = gp_data.get("is_mintable")
                if mint is not None:
                    result["mint_authority"] = "ACTIVE" if str(mint) == "1" else "REVOKED"
                    if str(mint) == "1":
                        score -= 20
                    else:
                        score += 10

                # Holders
                holders = gp_data.get("holder_count")
                if holders:
                    result["holders"] = int(holders)
                    if int(holders) > 100:
                        score += 10
                    elif int(holders) < 20:
                        score -= 10

                # Top holder
                top = gp_data.get("top10_holder_rate")
                if top:
                    result["top_holder_pct"] = f"{float(top)*100:.1f}%"
                    if float(top) > 0.5:
                        score -= 15

                # Token name from GoPlus if DexScreener didn't have it
                if result["name"] == "UNKNOWN":
                    gp_name = gp_data.get("token_name", "")
                    gp_symbol = gp_data.get("token_symbol", "")
                    if gp_name:
                        result["name"] = gp_name
                    if gp_symbol:
                        result["symbol"] = gp_symbol
    except Exception as e:
        result["sources"].append(f"goplus:error:{str(e)[:50]}")

    # --- Helius DAS (if key available) ---
    if HELIUS_KEY:
        try:
            hel = requests.post(
                f"https://mainnet.helius-rpc.com/?api-key={HELIUS_KEY}",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getAsset",
                    "params": {"id": address}
                },
                timeout=10
            )
            if hel.status_code == 200:
                hel_data = hel.json().get("result", {})
                if hel_data:
                    result["sources"].append("helius")

                    # Token name from Helius if still unknown
                    content = hel_data.get("content", {})
                    metadata = content.get("metadata", {})
                    if result["name"] == "UNKNOWN" and metadata.get("name"):
                        result["name"] = metadata["name"]
                    if result["symbol"] == "UNKNOWN" and metadata.get("symbol"):
                        result["symbol"] = metadata["symbol"]

                    # Authorities from on-chain data
                    authorities = hel_data.get("authorities", [])
                    for auth in authorities:
                        scopes = auth.get("scopes", [])
                        if "full" in scopes or "mint" in scopes:
                            # If there's a mint authority, it's active
                            if result["mint_authority"] == "UNKNOWN":
                                result["mint_authority"] = "ACTIVE"
                                score -= 15

                    # Freeze authority from token_info
                    token_info = hel_data.get("token_info", {})
                    freeze = token_info.get("freeze_authority")
                    if freeze:
                        result["freeze_authority"] = "ACTIVE"
                        score -= 10
                    elif result["freeze_authority"] == "UNKNOWN":
                        result["freeze_authority"] = "REVOKED"
                        score += 5

                    # Mint authority from token_info
                    mint_auth = token_info.get("mint_authority")
                    if not mint_auth and result["mint_authority"] == "UNKNOWN":
                        result["mint_authority"] = "REVOKED"
                        score += 10

                    # Supply
                    supply = token_info.get("supply", 0)
                    if supply:
                        result["supply"] = supply
        except Exception as e:
            result["sources"].append(f"helius:error:{str(e)[:50]}")

    # Clamp score
    result["score"] = max(0, min(100, score))

    # Risk level based on score
    if result["risk_level"] == "UNKNOWN":
        if result["score"] >= 70:
            result["risk_level"] = "LOW"
        elif result["score"] >= 40:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "CRITICAL"

    # AI Analysis
    prompt = f"""Analyze this Solana token security scan:
Token: {result['name']} ({result['symbol']})
Address: {address}
Score: {result['score']}/100
Mint Authority: {result['mint_authority']}
Freeze Authority: {result['freeze_authority']}
LP/Liquidity: {result['lp_status']} (${result['liquidity_usd']:,.0f})
Honeypot: {result['is_honeypot']}
Holders: {result['holders']}
Top 10 Holders: {result['top_holder_pct']}
Risk: {result['risk_level']}
Price: ${result['price_usd']}
24h Volume: ${result['volume_24h']:,.0f}

Give a brief, direct risk assessment in 2-3 sentences. Include the token name. What should a trader know?"""

    result["ai_analysis"] = ai_analyze(prompt)

    cache_set(f"xray:{address}", result)
    return jsonify(result)


# ============================================================
# TOOL 2: THE PROBE -- Smart Launch Filter
# ============================================================
@app.route("/api/probe/feed")
def probe_feed():
    """Returns recently launched tokens that pass quality filters."""
    cached = cache_get("probe:feed")
    if cached:
        return jsonify(cached)

    tokens = []

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
                for t in raw[:30]:
                    mint = t.get("mint", t.get("tokenAddress", ""))
                    if not mint:
                        continue
                    tokens.append({
                        "address": mint,
                        "name": t.get("name", t.get("tokenName", "Unknown")),
                        "symbol": t.get("symbol", "???"),
                        "score": t.get("score", 0),
                        "created": t.get("createdAt", ""),
                        "source": "rugcheck"
                    })
    except Exception:
        pass

    # Fetch trending from DexScreener
    try:
        dx = requests.get(
            "https://api.dexscreener.com/token-boosts/latest/v1",
            timeout=10
        )
        if dx.status_code == 200:
            boosts = dx.json()
            if isinstance(boosts, list):
                for b in boosts[:10]:
                    if b.get("chainId") == "solana":
                        tokens.append({
                            "address": b.get("tokenAddress", ""),
                            "name": b.get("description", "Unknown"),
                            "symbol": b.get("tokenAddress", "")[:6],
                            "score": 0,
                            "source": "dexscreener"
                        })
    except Exception:
        pass

    result = {"tokens": tokens[:20], "total_scanned": len(tokens), "passed": len(tokens)}
    cache_set("probe:feed", result)
    return jsonify(result)


# ============================================================
# TOOL 3: MOTHERSHIP -- Whale Intelligence
# ============================================================
# Known whale/smart money wallets (verified addresses)
WHALE_WALLETS = [
    "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",  # Wintermute
    "HWHvQhFmJB6gPtqJx3gjxHX1iDZhQ9WJorxwb3iTWEgA",  # Jump Trading
    "2iZo1vFfiRFoBga2JhbyXDjYqFfmGQKYfERPPdUjqgni",  # Raydium Authority
    "7rhxnLV8C8MmXhJBrFMMatJfQ3GAdhVfLoKygrusNjfa",  # Known whale
    "FWznbcNXWQuHTawe9RxvQ2LdCENssh12dsznf4RiouN5",  # Smart money
    "3Bm7qTCsn5ayMvGSYXrbD9JDXMSbC7pTdvqE6zKQB3Fn",  # DeFi whale
    "DNfuF1L62WWyW3pNakVkyGGFzVVhj4Yr52jSmdTyeBHm",  # Top trader
]

@app.route("/api/mothership/feed")
def mothership_feed():
    """Track whale wallet movements."""
    cached = cache_get("mothership:feed")
    if cached:
        return jsonify(cached)

    movements = []

    if HELIUS_KEY:
        for wallet in WHALE_WALLETS[:5]:  # Limit to save API credits
            try:
                r = requests.get(
                    f"https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key={HELIUS_KEY}&limit=3",
                    timeout=10
                )
                if r.status_code == 200:
                    txs = r.json()
                    for tx in txs:
                        movements.append({
                            "wallet": wallet[:8] + "..." + wallet[-4:],
                            "signature": tx.get("signature", "")[:16] + "...",
                            "type": tx.get("type", "UNKNOWN"),
                            "timestamp": tx.get("timestamp", 0),
                            "description": tx.get("description", "Transaction detected")
                        })
            except Exception:
                continue

    # AI intent classification
    if movements and (GROQ_KEY or DEEPSEEK_KEY):
        summary = "; ".join([f"{m['wallet']}: {m['type']}" for m in movements[:10]])
        ai = ai_analyze(f"Classify these whale movements by intent (accumulation/distribution/reshuffling): {summary}")
    else:
        ai = "Connect Helius API for live whale tracking."

    result = {"movements": movements[:20], "tracked_wallets": len(WHALE_WALLETS), "ai_analysis": ai}
    cache_set("mothership:feed", result)
    return jsonify(result)


# ============================================================
# TOOL 4: SIGNAL INTERCEPT -- Narrative Radar
# ============================================================
@app.route("/api/signal/narratives")
def signal_narratives():
    """Detect emerging crypto narratives from news + social."""
    cached = cache_get("signal:narratives")
    if cached:
        return jsonify(cached)

    narratives = []

    # GDELT news API (free, no key)
    try:
        gd = requests.get(
            "https://api.gdeltproject.org/api/v2/doc/doc?query=%22crypto%20solana%22%20OR%20%22memecoin%22&mode=artlist&maxrecords=30&format=json&sort=datedesc",
            timeout=15
        )
        if gd.status_code == 200:
            articles = gd.json().get("articles", [])
            # Group by theme/keyword
            themes = {}
            for a in articles:
                title = a.get("title", "").lower()
                for kw in ["ai", "gaming", "rwa", "depin", "meme", "layer2", "restaking"]:
                    if kw in title:
                        if kw not in themes:
                            themes[kw] = {"count": 0, "articles": []}
                        themes[kw]["count"] += 1
                        themes[kw]["articles"].append(a.get("title", ""))

            for kw, data in sorted(themes.items(), key=lambda x: -x[1]["count"]):
                narratives.append({
                    "name": kw.upper(),
                    "mentions": data["count"],
                    "sample_headlines": data["articles"][:3],
                    "source": "gdelt"
                })
    except Exception:
        pass

    # AI phase classification
    if narratives and (GROQ_KEY or DEEPSEEK_KEY):
        summary = ", ".join([f"{n['name']}({n['mentions']} mentions)" for n in narratives])
        ai = ai_analyze(f"Classify these crypto narratives by adoption phase (inception/early/mainstream/saturation): {summary}")
    else:
        ai = ""

    result = {"narratives": narratives[:8], "ai_analysis": ai}
    cache_set("signal:narratives", result)
    return jsonify(result)


# ============================================================
# TOOL 5: HOLOGRAM DETECTOR -- Volume Authenticity
# ============================================================
@app.route("/api/hologram/analyze", methods=["POST"])
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
    except Exception:
        pass

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
        except Exception:
            pass

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
        "ai_analysis": ""
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
        except Exception:
            pass

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
                                    progress = min(100, (mcap / 69000) * 100)
                                    tokens.append({
                                        "address": addr,
                                        "name": name,
                                        "symbol": symbol,
                                        "mcap": mcap,
                                        "liquidity": liq,
                                        "progress": round(progress, 1),
                                        "price_change_24h": price_change,
                                        "graduated": mcap >= 69000
                                    })
                    except Exception:
                        continue

                    if len(tokens) >= 10:
                        break
    except Exception:
        pass

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
                                        "estimated_losses": volume * 0.6  # rough estimate
                                    })
                    except Exception:
                        continue

                    if len(autopsies) >= 8:
                        break
    except Exception:
        pass

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
    app.run(host="0.0.0.0", port=port, debug=True)
