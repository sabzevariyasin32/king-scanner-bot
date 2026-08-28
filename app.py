import os
import requests
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, CommandHandler

BOT_TOKEN = "8903346902:AAF3XiPorSqDQc4kCnZFMW-rRSo7EuH8yLU"
VT_API_KEY = "7fc78536566a970658bdb8f98bdbb5c5f90d9d52e58caf01173af9bfbed6b00d"


async def start(update: Update, context):
    await update.message.reply_text(
        "سلام به کینگ اسکنر خوش اومدی \nحالا محتوا مورد نظرتو بفرست تا اسکن کنم"
    )


async def scan_file(update: Update, context):
    file = update.message.document
    file_name = file.file_name
    file_size = file.file_size

    await update.message.reply_text(f" در حال اسکن {file_name}...")

    file_obj = await file.get_file()
    os.makedirs("download", exist_ok=True)
    file_path = f"download/{file_name}"
    await file_obj.download_to_drive(file_path)

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report = requests.get(report_url, headers=headers).json()
        stats = report["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            result_text = " مخرب"
        elif suspicious > 0:
            result_text = " مشکوک"
        else:
            result_text = " سالم"

        message = (
            f"{result_text}\n"
            f" مخرب: {malicious}\n"
            f"️ مشکوک: {suspicious}\n"
            f" سالم: {undetected}\n"
            f" {file_name}"
        )

        await update.message.reply_text(message)

    else:
        await update.message.reply_text(" خطا در اسکن. دوباره تلاش کن.")

    if os.path.exists(file_path):
        os.remove(file_path)


async def scan_url(update: Update, context):
    url = update.message.text
    await update.message.reply_text(" در حال اسکن لینک...")

    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data=data,
        headers=headers
    )

    if response.status_code == 200:
        result = response.json()
        analysis_id = result["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report = requests.get(report_url, headers=headers).json()
        stats = report["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)

        if malicious > 0:
            await update.message.reply_text(" لینک مخرب است!")
        else:
            await update.message.reply_text(" لینک سالم است.")
    else:
        await update.message.reply_text(" خطا در اسکن لینک.")


def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, scan_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_url))

    print(" ربات روشن شد...")
    app.run_polling()


if __name__ == "__main__":
    main()
