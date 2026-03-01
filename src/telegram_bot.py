import os
import time
from collections import defaultdict, deque

import httpx
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

API_URL = os.getenv("API_URL", "http://api:8000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "dev-secret")

AUTHORIZED_USERS: set[int] = set(
    int(uid.strip())
    for uid in os.getenv("TELEGRAM_AUTHORIZED_USERS", "").split(",")
    if uid.strip().isdigit()
)

_RATE_LIMIT = int(os.getenv("RATE_LIMIT_TELEGRAM_USER", "10"))

_last_text: dict[int, str] = {}
_user_timestamps: dict[int, deque] = defaultdict(deque)

_SIGNAL_LABELS_PT = {
    "Suspicious link or brand spoofing": "Link suspeito ou imitação de marca conhecida",
    "Hard urgency or threat tone": "Linguagem de urgência ou ameaça",
    "Direct financial request": "Solicitação de dados financeiros (Pix, senha, token)",
    "Legal pressure or fake subpoena bait": "Pressão jurídica falsa (processo, intimação)",
    "Brand impersonation via look-alike domain": "Domínio imitando uma marca oficial",
}

_RISK_PT = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO"}


def _is_authorized(user_id: int) -> bool:
    if not AUTHORIZED_USERS:
        return True
    return user_id in AUTHORIZED_USERS


def _is_rate_limited(user_id: int) -> bool:
    now = time.monotonic()
    dq = _user_timestamps[user_id]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return True
    dq.append(now)
    return False


def _build_pt(result: dict) -> str:
    risk = _RISK_PT.get(result["risk_level"], result["risk_level"])
    score = int(result["final_risk_score"] * 100)
    verdict = "FRAUDE DETECTADA" if result["is_fraud"] else "MENSAGEM SEGURA"
    domains = list(dict.fromkeys(result["suspicious_domains"] + result["look_alike_domains"]))

    lines = [
        "<b>Análise de Segurança</b>",
        "",
        f"Veredicto: <b>{verdict}</b>",
        f"Nível de Risco: <b>{risk}</b> ({score}%)",
    ]

    if result["signals"]:
        lines += ["", "<b>Motivos Identificados:</b>"]
        for s in result["signals"]:
            lines.append(f"- {_SIGNAL_LABELS_PT.get(s, s)}")

    if domains:
        lines += ["", "<b>Domínios Suspeitos:</b>"]
        for d in domains:
            lines.append(f"- {d}")

    lines += ["", "Use /feedback se esta análise estiver incorreta."]
    return "\n".join(lines)


def _build_en(result: dict) -> str:
    risk = result["risk_level"]
    score = int(result["final_risk_score"] * 100)
    verdict = "FRAUD DETECTED" if result["is_fraud"] else "SAFE MESSAGE"
    domains = list(dict.fromkeys(result["suspicious_domains"] + result["look_alike_domains"]))

    lines = [
        "<b>Security Analysis</b>",
        "",
        f"Verdict: <b>{verdict}</b>",
        f"Risk Level: <b>{risk}</b> ({score}%)",
    ]

    if result["signals"]:
        lines += ["", "<b>Detected Signals:</b>"]
        for s in result["signals"]:
            lines.append(f"- {s}")

    if domains:
        lines += ["", "<b>Suspicious Domains:</b>"]
        for d in domains:
            lines.append(f"- {d}")

    lines += ["", "Use /feedback to report an incorrect analysis."]
    return "\n".join(lines)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Encaminhe uma mensagem suspeita para análise.\n"
        "Forward a suspicious message for analysis."
    )


async def cmd_feedback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id

    if not _is_authorized(user_id):
        await update.message.reply_text(
            "Acesso não autorizado. / Unauthorized."
        )
        return

    text = _last_text.get(user_id)

    if not text:
        await update.message.reply_text(
            "Nenhuma mensagem analisada recentemente. / No recent message analyzed."
        )
        return

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_URL}/api/v1/feedback",
            params={"text": text, "is_fraud": False},
            headers={"X-Admin-Key": ADMIN_API_KEY},
            timeout=10,
        )

    if resp.status_code == 200:
        await update.message.reply_text(
            "Falso positivo registrado. Obrigado! / False positive recorded. Thank you!"
        )
    else:
        await update.message.reply_text(
            "Erro ao registrar feedback. / Feedback error."
        )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id

    if not _is_authorized(user_id):
        await update.message.reply_text(
            "Acesso não autorizado. / Unauthorized."
        )
        return

    if _is_rate_limited(user_id):
        await update.message.reply_text(
            "Limite atingido. Tente novamente em 1 minuto. / Rate limit exceeded. Try again in 1 minute."
        )
        return

    text = " ".join(update.message.text.split())

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_URL}/api/v1/detect",
            json={"text": text, "source": "telegram"},
            timeout=15,
        )

    if resp.status_code != 200:
        await update.message.reply_text(
            "Erro ao analisar mensagem. / Analysis error."
        )
        return

    result = resp.json()
    _last_text[user_id] = text

    lang = result.get("language", "pt")
    reply = _build_pt(result) if lang == "pt" else _build_en(result)

    await update.message.reply_text(reply, parse_mode="HTML")


def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("feedback", cmd_feedback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()


if __name__ == "__main__":
    main()
