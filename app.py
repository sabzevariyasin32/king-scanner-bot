import os
import time
import asyncio
import hashlib
import requests

from flask import Flask
from threading import Thread

from telegram import Update
from telegram.ext import (
    Application,
    MessageHandler,
    filters,
    CommandHandler
)


BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

MAX_SCAN_WAIT = 240
SCAN_INTERVAL = 20


web_app = Flask(__name__)


@web_app.route("/")
def home():
    return "King Scanner Bot is running."


def run_web():
    port = int(os.environ.get("PORT", 10000))
    web_app.run(
        host="0.0.0.0",
        port=port
    )


def get_headers():
    return {
        "x-apikey": VT_API_KEY
    }


def upload_file_to_virustotal(file_path):
    url = f"{VT_BASE_URL}/files"

    with open(file_path, "rb") as file:
        files = {
            "file": file
        }

        response = requests.post(
            url,
            files=files,
            headers=get_headers(),
            timeout=60
        )

    return response


def get_analysis(analysis_id):
    url = f"{VT_BASE_URL}/analyses/{analysis_id}"

    response = requests.get(
        url,
        headers=get_headers(),
        timeout=30
    )

    return response


def wait_for_analysis(analysis_id):
    start_time = time.time()

    while time.time() - start_time < MAX_SCAN_WAIT:

        response = get_analysis(analysis_id)

        if response.status_code != 200:
            return None, "خطا در دریافت وضعیت اسکن."

        data = response.json()

        status = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("status")
        )

        if status == "completed":
            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("stats", {})
            )

            return stats, None

        time.sleep(SCAN_INTERVAL)

    return None, "زمان اسکن بیش از حد طولانی شد."


def get_existing_file_report(file_hash):
    url = f"{VT_BASE_URL}/files/{file_hash}"

    response = requests.get(
        url,
        headers=get_headers(),
        timeout=30
    )

    return response


def scan_file_with_virustotal(file_path):
    file_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            file_hash.update(chunk)

    sha256 = file_hash.hexdigest()

    existing_response = get_existing_file_report(sha256)

    if existing_response.status_code == 200:
        data = existing_response.json()

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        if stats:
            return stats, None

    upload_response = upload_file_to_virustotal(file_path)

    if upload_response.status_code != 200:
        return None, "خطا در ارسال فایل به VirusTotal."

    upload_data = upload_response.json()

    analysis_id = (
        upload_data
        .get("data", {})
        .get("id")
    )

    if not analysis_id:
        return None, "شناسه اسکن دریافت نشد."

    return wait_for_analysis(analysis_id)


async def start(update: Update, context):
    await update.message.reply_text(
        "سلام به کینگ اسکنر خوش اومدی\n"
        "حالا محتوا مورد نظرتو بفرست تا اسکن کنم"
    )


async def scan_file(update: Update, context):
    document = update.message.document

    file_name = document.file_name

    await update.message.reply_text(
        f"در حال اسکن {file_name}..."
    )

    file_obj = await document.get_file()

    os.makedirs("download", exist_ok=True)

    safe_file_name = os.path.basename(file_name)

    file_path = os.path.join(
        "download",
        safe_file_name
    )

    try:
        await file_obj.download_to_drive(file_path)

        stats, error = await asyncio.to_thread(
            scan_file_with_virustotal,
            file_path
        )

        if error:
            await update.message.reply_text(error)
            return

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            result_text = "مخرب"
        elif suspicious > 0:
            result_text = "مشکوک"
        else:
            result_text = "سالم"

        message = (
            f"نتیجه اسکن: {result_text}\n"
            f"مخرب: {malicious}\n"
            f"مشکوک: {suspicious}\n"
            f"سالم: {harmless}\n"
            f"شناسایی نشده: {undetected}\n"
            f"نام فایل: {file_name}"
        )

        await update.message.reply_text(message)

    except Exception as error:
        print(f"File scan error: {error}")

        await update.message.reply_text(
            "خطایی هنگام اسکن فایل رخ داد."
        )

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


def submit_url_to_virustotal(url_to_scan):
    endpoint = f"{VT_BASE_URL}/urls"

    response = requests.post(
        endpoint,
        data={
            "url": url_to_scan
        },
        headers=get_headers(),
        timeout=30
    )

    return response


def scan_url_with_virustotal(url_to_scan):
    response = submit_url_to_virustotal(url_to_scan)

    if response.status_code != 200:
        return None, "خطا در ارسال لینک به VirusTotal."

    data = response.json()

    analysis_id = (
        data
        .get("data", {})
        .get("id")
    )

    if not analysis_id:
        return None, "شناسه اسکن لینک دریافت نشد."

    return wait_for_analysis(analysis_id)


async def scan_url(update: Update, context):
    url = update.message.text.strip()

    await update.message.reply_text(
        "در حال اسکن لینک..."
    )

    try:
        stats, error = await asyncio.to_thread(
            scan_url_with_virustotal,
            url
        )

        if error:
            await update.message.reply_text(error)
            return

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            result_text = "لینک مخرب است."
        elif suspicious > 0:
            result_text = "لینک مشکوک است."
        else:
            result_text = "لینک سالم است."

        message = (
            f"{result_text}\n"
            f"مخرب: {malicious}\n"
            f"مشکوک: {suspicious}\n"
            f"سالم: {harmless}\n"
            f"شناسایی نشده: {undetected}"
        )

        await update.message.reply_text(message)

    except Exception as error:
        print(f"URL scan error: {error}")

        await update.message.reply_text(
            "خطایی هنگام اسکن لینک رخ داد."
        )


def main():
    if not BOT_TOKEN:
        raise ValueError(
            "BOT_TOKEN environment variable is not set."
        )

    if not VT_API_KEY:
        raise ValueError(
            "VT_API_KEY environment variable is not set."
        )

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(
        CommandHandler(
            "start",
            start
        )
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

    print("ربات روشن شد.")

    app.run_polling()


if __name__ == "__main__":

    Thread(
        target=run_web,
        daemon=True
    ).start()

    main()
