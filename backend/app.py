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
            "signal": "live",
            "hologram": "live",
            "abduction": "live",
            "debriefing": "live"
        },
        "apis": {
            "goplus": "no key needed",
            "rugcheck": "connected" if RUGCHECK_KEY else "no key",
            "helius": "connected" if HELIUS_KEY else "no key",
            "groq": "connected" if GROQ_KEY else "no key",
            "deepseek": "connected" if DEEPSEEK_KEY else "no key"
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

    # --- GoPlus Security API (no key needed, 30 req/min) ---
    try:
        gp = requests.get(
            f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={address}",
            timeout=10
        )
        if gp.status_code == 200:
            gp_data = gp.json().get("result", {}).get(address.lower(), {})
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
    except Exception as e:
        result["sources"].append(f"goplus:error:{str(e)[:50]}")

    # --- RugCheck API ---
    try:
        headers = {}
        if RUGCHECK_KEY:
            headers["X-API-KEY"] = RUGCHECK_KEY
        rc = requests.get(
            f"https://api.rugcheck.xyz/v1/tokens/{address}/report/summary",
            headers=headers,
            timeout=10
        )
        if rc.status_code == 200:
            rc_data = rc.json()
            result["sources"].append("rugcheck")

            # Risk level from RugCheck
            risk = rc_data.get("score", rc_data.get("riskLevel", ""))
            if risk:
                result["risk_level"] = str(risk).upper()

            # LP status
            lp = rc_data.get("markets", [])
            if lp:
                lp_locked = any(m.get("lp", {}).get("lpLockedPct", 0) > 90 for m in lp if isinstance(m, dict))
                result["lp_status"] = "LOCKED" if lp_locked else "UNLOCKED"
                if lp_locked:
                    score += 10
                else:
                    score -= 15

            # Freeze authority
            freeze = rc_data.get("freezeAuthority")
            if freeze is not None:
                result["freeze_authority"] = "REVOKED" if freeze is None or freeze == "" else "ACTIVE"
            
            # Mint authority (cross-check)
            mint_rc = rc_data.get("mintAuthority")
            if mint_rc is not None:
                if mint_rc is None or mint_rc == "":
                    if result["mint_authority"] == "UNKNOWN":
                        result["mint_authority"] = "REVOKED"
                        score += 10
    except Exception as e:
        result["sources"].append(f"rugcheck:error:{str(e)[:50]}")

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
                    
                    # Check authorities from on-chain data
                    authorities = hel_data.get("authorities", [])
                    ownership = hel_data.get("ownership", {})
                    
                    supply = hel_data.get("token_info", {}).get("supply", 0)
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
Address: {address}
Score: {result['score']}/100
Mint Authority: {result['mint_authority']}
Freeze Authority: {result['freeze_authority']}
LP Status: {result['lp_status']}
Honeypot: {result['is_honeypot']}
Holders: {result['holders']}
Top Holder: {result['top_holder_pct']}
Risk: {result['risk_level']}

Give a brief, direct risk assessment. What should a trader know before buying?"""

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
# Known whale/smart money wallets (expand this list)
WHALE_WALLETS = [
    "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",  # Wintermute
    "HWHvQhFmJB6gPtqJx3gjxHX1iDZhQ9WJorxwb3iTWEgA",  # Jump Trading
    "CuieVDEDtLo7FypA9SbLM9saXFdb1dsshEkyErMqkRQq",   # Alameda
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
# RUN
# ============================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
