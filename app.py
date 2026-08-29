import os
import requests
from flask import Flask
from threading import Thread

from telegram import Update
from telegram.ext import Application, MessageHandler, filters, CommandHandler


BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")


web_app = Flask(__name__)


@web_app.route("/")
def home():
    return "King Scanner Bot is running!"


def run_web():
    port = int(os.environ.get("PORT", 10000))
    web_app.run(host="0.0.0.0", port=port)


async def start(update: Update, context):
    await update.message.reply_text(
        "سلام به کینگ اسکنر خوش اومدی\n"
        "حالا محتوا مورد نظرتو بفرست تا اسکن کنم"
    )


async def scan_file(update: Update, context):
    file = update.message.document
    file_name = file.file_name

    await update.message.reply_text(
        f"در حال اسکن {file_name}..."
    )

    file_obj = await file.get_file()

    os.makedirs("download", exist_ok=True)

    file_path = f"download/{file_name}"

    await file_obj.download_to_drive(file_path)

    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "x-apikey": VT_API_KEY
    }

    with open(file_path, "rb") as f:
        files = {
            "file": f
        }

        response = requests.post(
            url,
            files=files,
            headers=headers
        )

    if response.status_code == 200:
        result = response.json()

        analysis_id = result["data"]["id"]

        report_url = (
            f"https://www.virustotal.com/api/v3/analyses/"
            f"{analysis_id}"
        )

        report = requests.get(
            report_url,
            headers=headers
        ).json()

        stats = report["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            result_text = "مخرب"
        elif suspicious > 0:
            result_text = "مشکوک"
        else:
            result_text = "سالم"

        message = (
            f"{result_text}\n"
            f"مخرب: {malicious}\n"
            f"مشکوک: {suspicious}\n"
            f"سالم: {undetected}\n"
            f"{file_name}"
        )

        await update.message.reply_text(message)

    else:
        await update.message.reply_text(
            "خطا در اسکن. دوباره تلاش کن."
        )

    if os.path.exists(file_path):
        os.remove(file_path)


async def scan_url(update: Update, context):
    url = update.message.text

    await update.message.reply_text(
        "در حال اسکن لینک..."
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    data = {
        "url": url
    }

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data=data,
        headers=headers
    )

    if response.status_code == 200:
        result = response.json()

        analysis_id = result["data"]["id"]

        report_url = (
            f"https://www.virustotal.com/api/v3/analyses/"
            f"{analysis_id}"
        )

        report = requests.get(
            report_url,
            headers=headers
        ).json()

        stats = report["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)

        if malicious > 0:
            await update.message.reply_text(
                "لینک مخرب است!"
            )
        else:
            await update.message.reply_text(
                "لینک سالم است."
            )

    else:
        await update.message.reply_text(
            "خطا در اسکن لینک."
        )


def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(
        CommandHandler("start", start)
    )

    app.add_handler(
        MessageHandler(
            filters.Document.ALL,
            scan_file
        )
    )

    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            scan_url
        )
    )

    print("ربات روشن شد...")

    app.run_polling()


if __name__ == "__main__":
    Thread(
        target=run_web,
        daemon=True
    ).start()

    main()
