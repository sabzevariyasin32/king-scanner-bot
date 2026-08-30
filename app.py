import os
import time
import asyncio
import hashlib
import base64
import requests

from flask import Flask, request

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)


# ============================================================
# تنظیمات اصلی
# ============================================================

# توکن ربات تلگرام
BOT_TOKEN = os.getenv("BOT_TOKEN")

# API Key مربوط به VirusTotal
VT_API_KEY = os.getenv("VT_API_KEY")

# آدرس اصلی API ویروس‌توتال
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ------------------------------------------------------------
# آدرس Webhook
#
# Render معمولاً متغیر RENDER_EXTERNAL_URL را در اختیار برنامه
# قرار می‌دهد.
#
# اگر وجود نداشت، می‌توانی WEBHOOK_URL را در Environment
# Variables به صورت دستی قرار بدهی.
# ------------------------------------------------------------

RENDER_URL = os.getenv("RENDER_EXTERNAL_URL")

WEBHOOK_URL = os.getenv("WEBHOOK_URL")

if not WEBHOOK_URL and RENDER_URL:
    WEBHOOK_URL = RENDER_URL.rstrip("/") + "/webhook"

# حداکثر زمان انتظار برای نتیجه VirusTotal
MAX_SCAN_WAIT = 120

# هر چند ثانیه وضعیت اسکن را بررسی کنیم
SCAN_INTERVAL = 3

# ------------------------------------------------------------
# محدودیت تقریبی فایل برای Telegram Bot API
#
# اگر فایل بزرگ‌تر از این باشد، اصلاً تلاش نمی‌کنیم دانلودش
# کنیم تا خطای File is too big نگیریم.
# ------------------------------------------------------------

MAX_FILE_SIZE = 20 * 1024 * 1024


# ============================================================
# Flask
# ============================================================

web_app = Flask(__name__)


# ============================================================
# متغیرهای مربوط به Telegram Application
# ============================================================

telegram_app = None

# Event Loop اختصاصی ربات
telegram_loop = None


# ============================================================
# صفحه اصلی Render
# ============================================================

@web_app.route("/")
def home():

    return "King Scanner Bot is running."


# ============================================================
# Webhook تلگرام
# ============================================================

@web_app.route("/webhook", methods=["POST"])
def telegram_webhook():

    global telegram_app
    global telegram_loop

    # اگر ربات هنوز آماده نشده باشد
    if telegram_app is None or telegram_loop is None:

        return "Bot is starting", 503

    try:

        # دریافت JSON ارسال‌شده توسط Telegram
        data = request.get_json(force=True)

        # تبدیل JSON به Update تلگرام
        update = Update.de_json(
            data,
            telegram_app.bot
        )

        # ارسال Update به Event Loop ربات
        asyncio.run_coroutine_threadsafe(
            telegram_app.process_update(update),
            telegram_loop
        )

        # سریع پاسخ 200 می‌دهیم
        # تا Telegram بداند درخواست دریافت شده
        return "OK", 200

    except Exception as error:

        print(
            f"Webhook error: {error}"
        )

        return "Error", 500


# ============================================================
# اجرای Flask
# ============================================================

def run_web():

    # Render پورت را در PORT قرار می‌دهد
    port = int(
        os.environ.get(
            "PORT",
            10000
        )
    )

    print(
        f"Starting Flask on port {port}"
    )

    web_app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )


# ============================================================
# Header مربوط به VirusTotal
# ============================================================

def get_headers():

    return {
        "x-apikey": VT_API_KEY
    }


# ============================================================
# بررسی فایل در VirusTotal با SHA256
# ============================================================

def get_file_report(file_hash):

    url = (
        f"{VT_BASE_URL}/files/"
        f"{file_hash}"
    )

    try:

        response = requests.get(
            url,
            headers=get_headers(),
            timeout=15
        )

        return response

    except requests.RequestException as error:

        print(
            f"VirusTotal file report error: {error}"
        )

        return None


# ============================================================
# آپلود فایل به VirusTotal
# ============================================================

def upload_file(file_path):

    url = f"{VT_BASE_URL}/files"

    try:

        # باز کردن فایل به صورت Binary
        with open(
            file_path,
            "rb"
        ) as file:

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

    except requests.RequestException as error:

        print(
            f"VirusTotal upload error: {error}"
        )

        return None


# ============================================================
# گرفتن وضعیت Analysis
# ============================================================

def get_analysis(analysis_id):

    url = (
        f"{VT_BASE_URL}/analyses/"
        f"{analysis_id}"
    )

    try:

        response = requests.get(
            url,
            headers=get_headers(),
            timeout=15
        )

        return response

    except requests.RequestException as error:

        print(
            f"Analysis request error: {error}"
        )

        return None


# ============================================================
# منتظر ماندن برای تمام شدن اسکن
# ============================================================

def wait_for_analysis(analysis_id):

    # زمان شروع
    start_time = time.time()

    while (
        time.time() - start_time
        < MAX_SCAN_WAIT
    ):

        # گرفتن وضعیت اسکن
        response = get_analysis(
            analysis_id
        )

        # خطای اتصال
        if response is None:

            return (
                None,
                "ارتباط با VirusTotal برقرار نشد."
            )

        # اگر پاسخ موفق نبود
        if response.status_code != 200:

            print(
                f"Analysis HTTP error: "
                f"{response.status_code}"
            )

            return (
                None,
                "خطا در دریافت وضعیت اسکن."
            )

        try:

            data = response.json()

        except ValueError:

            return (
                None,
                "پاسخ نامعتبر از VirusTotal دریافت شد."
            )

        # گرفتن attributes
        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        # وضعیت اسکن
        status = attributes.get(
            "status"
        )

        print(
            f"VirusTotal status: {status}"
        )

        # اگر اسکن تمام شده
        if status == "completed":

            stats = attributes.get(
                "stats",
                {}
            )

            return stats, None

        # چند ثانیه صبر
        time.sleep(
            SCAN_INTERVAL
        )

    # زمان بیش از حد طولانی شد
    return (
        None,
        "زمان اسکن بیش از حد طولانی شد."
    )


# ============================================================
# اسکن فایل
# ============================================================

def scan_file(file_path):

    print(
        f"Starting file scan: {file_path}"
    )

    # ساخت SHA256
    sha256 = hashlib.sha256()

    # خواندن فایل به صورت تکه‌ای
    with open(
        file_path,
        "rb"
    ) as file:

        while True:

            # هر بار 1MB
            chunk = file.read(
                1024 * 1024
            )

            # پایان فایل
            if not chunk:
                break

            # اضافه کردن به SHA256
            sha256.update(
                chunk
            )

    # Hash نهایی
    file_hash = sha256.hexdigest()

    print(
        f"SHA256: {file_hash}"
    )

    # ========================================================
    # اول بررسی می‌کنیم آیا VirusTotal قبلاً فایل را دارد
    # ========================================================

    existing = get_file_report(
        file_hash
    )

    if (
        existing is not None
        and existing.status_code == 200
    ):

        try:

            data = existing.json()

            attributes = (
                data
                .get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            if stats:

                print(
                    "File already exists "
                    "in VirusTotal."
                )

                return stats, None

        except ValueError:

            pass

    # ========================================================
    # فایل قبلاً وجود نداشته
    # ========================================================

    print(
        "Uploading file to VirusTotal..."
    )

    response = upload_file(
        file_path
    )

    if response is None:

        return (
            None,
            "ارتباط با VirusTotal برقرار نشد."
        )

    # VirusTotal ممکن است 200 یا 201 برگرداند
    if response.status_code not in (
        200,
        201
    ):

        print(
            f"Upload HTTP error: "
            f"{response.status_code}"
        )

        print(
            response.text[:500]
        )

        return (
            None,
            "خطا در ارسال فایل به VirusTotal."
        )

    try:

        data = response.json()

    except ValueError:

        return (
            None,
            "پاسخ نامعتبر از VirusTotal دریافت شد."
        )

    # گرفتن Analysis ID
    analysis_id = (
        data
        .get("data", {})
        .get("id")
    )

    if not analysis_id:

        return (
            None,
            "شناسه اسکن دریافت نشد."
        )

    print(
        f"Analysis ID: {analysis_id}"
    )

    # انتظار برای نتیجه
    return wait_for_analysis(
        analysis_id
    )


# ============================================================
# ساخت URL ID برای VirusTotal
# ============================================================

def get_url_id(url):

    # تبدیل URL به Base64
    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    # حذف = از انتها
    return encoded.rstrip("=")


# ============================================================
# بررسی گزارش قبلی URL
# ============================================================

def get_url_report(url):

    url_id = get_url_id(
        url
    )

    endpoint = (
        f"{VT_BASE_URL}/urls/"
        f"{url_id}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15
        )

        return response

    except requests.RequestException as error:

        print(
            f"URL report error: {error}"
        )

        return None


# ============================================================
# ارسال URL جدید
# ============================================================

def submit_url(url):

    endpoint = (
        f"{VT_BASE_URL}/urls"
    )

    try:

        response = requests.post(
            endpoint,
            data={
                "url": url
            },
            headers=get_headers(),
            timeout=30
        )

        return response

    except requests.RequestException as error:

        print(
            f"URL submit error: {error}"
        )

        return None


# ============================================================
# اسکن URL
# ============================================================

def scan_url_request(url):

    print(
        f"Starting URL scan: {url}"
    )

    # ========================================================
    # بررسی گزارش قبلی
    # ========================================================

    existing = get_url_report(
        url
    )

    if (
        existing is not None
        and existing.status_code == 200
    ):

        try:

            data = existing.json()

            attributes = (
                data
                .get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            if stats:

                print(
                    "URL already exists "
                    "in VirusTotal."
                )

                return stats, None

        except ValueError:

            pass

    # ========================================================
    # URL جدید
    # ========================================================

    print(
        "Submitting URL to VirusTotal..."
    )

    response = submit_url(
        url
    )

    if response is None:

        return (
            None,
            "ارتباط با VirusTotal برقرار نشد."
        )

    if response.status_code not in (
        200,
        201
    ):

        print(
            f"URL submit HTTP error: "
            f"{response.status_code}"
        )

        print(
            response.text[:500]
        )

        return (
            None,
            "خطا در ارسال لینک به VirusTotal."
        )

    try:

        data = response.json()

    except ValueError:

        return (
            None,
            "پاسخ نامعتبر از VirusTotal دریافت شد."
        )

    # Analysis ID
    analysis_id = (
        data
        .get("data", {})
        .get("id")
    )

    if not analysis_id:

        return (
            None,
            "شناسه اسکن لینک دریافت نشد."
        )

    print(
        f"URL Analysis ID: {analysis_id}"
    )

    # انتظار برای نتیجه
    return wait_for_analysis(
        analysis_id
    )


# ============================================================
# ساخت متن نتیجه اسکن
# ============================================================

def make_result(
    stats,
    file_name=None
):

    # تعداد تشخیص مخرب
    malicious = stats.get(
        "malicious",
        0
    )

    # تعداد مشکوک
    suspicious = stats.get(
        "suspicious",
        0
    )

    # تعداد سالم
    harmless = stats.get(
        "harmless",
        0
    )

    # تعداد شناسایی نشده
    undetected = stats.get(
        "undetected",
        0
    )

    # ========================================================
    # تعیین وضعیت
    # ========================================================

    if malicious > 0:

        result = "مخرب"

    elif suspicious > 0:

        result = "مشکوک"

    else:

        result = "سالم"

    # ========================================================
    # ساخت پیام
    # ========================================================

    message = (
        f"نتیجه اسکن: {result}\n"
        f"مخرب: {malicious}\n"
        f"مشکوک: {suspicious}\n"
        f"سالم: {harmless}\n"
        f"شناسایی نشده: {undetected}"
    )

    # اگر فایل است اسم فایل را اضافه کن
    if file_name:

        message += (
            f"\nنام فایل: {file_name}"
        )

    return message


# ============================================================
# دستور /start
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    await update.message.reply_text(
        "سلام به کینگ اسکنر خوش اومدی\n"
        "فایل یا لینک مورد نظرت رو بفرست تا اسکن کنم."
    )


# ============================================================
# دریافت فایل
# ============================================================

async def scan_file_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    # گرفتن اطلاعات فایل
    document = update.message.document

    # اسم فایل
    file_name = document.file_name

    # اندازه فایل
    file_size = document.file_size or 0

    print(
        f"Received file: "
        f"{file_name} "
        f"({file_size} bytes)"
    )

    # ========================================================
    # بررسی حجم قبل از دانلود
    # ========================================================

    if file_size > MAX_FILE_SIZE:

        await update.message.reply_text(
            "حجم این فایل بیشتر از حد مجاز است."
        )

        print(
            "File rejected because it is too big."
        )

        return

    # پیام وضعیت
    await update.message.reply_text(
        f"در حال اسکن {file_name}..."
    )

    # ========================================================
    # دریافت فایل از Telegram
    # ========================================================

    try:

        file_obj = await document.get_file()

    except Exception as error:

        print(
            f"Telegram get file error: {error}"
        )

        await update.message.reply_text(
            "دریافت فایل از تلگرام با خطا مواجه شد."
        )

        return

    # ساخت پوشه موقت
    os.makedirs(
        "download",
        exist_ok=True
    )

    # جلوگیری از مسیرهای خطرناک
    safe_name = os.path.basename(
        file_name
    )

    # نام یکتا برای فایل
    file_path = os.path.join(
        "download",
        f"{int(time.time())}_{safe_name}"
    )

    try:

        # ====================================================
        # دانلود فایل
        # ====================================================

        print(
            f"Downloading file: {file_name}"
        )

        await file_obj.download_to_drive(
            file_path
        )

        print(
            "File downloaded successfully."
        )

        # ====================================================
        # اسکن در Thread جدا
        # ====================================================

        stats, error = await asyncio.to_thread(
            scan_file,
            file_path
        )

        # اگر خطا وجود داشت
        if error:

            await update.message.reply_text(
                error
            )

            return

        # ساخت نتیجه
        message = make_result(
            stats,
            file_name
        )

        # ارسال نتیجه
        await update.message.reply_text(
            message
        )

    except Exception as error:

        print(
            f"File scan error: {error}"
        )

        await update.message.reply_text(
            "خطایی هنگام اسکن فایل رخ داد."
        )

    finally:

        # ====================================================
        # حذف فایل موقت
        # ====================================================

        if (
            file_path
            and os.path.exists(file_path)
        ):

            try:

                os.remove(
                    file_path
                )

                print(
                    "Temporary file deleted."
                )

            except Exception as error:

                print(
                    f"File delete error: {error}"
                )


# ============================================================
# بررسی ساده URL
# ============================================================

def is_valid_url(text):

    text = text.strip()

    return (
        text.startswith("http://")
        or text.startswith("https://")
    )


# ============================================================
# دریافت لینک
# ============================================================

async def scan_url_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    # گرفتن متن
    url = update.message.text.strip()

    # ========================================================
    # اگر متن URL نبود
    # ========================================================

    if not is_valid_url(url):

        await update.message.reply_text(
            "لطفاً یک لینک معتبر با http:// یا https:// ارسال کن."
        )

        return

    # اطلاع به کاربر
    await update.message.reply_text(
        "در حال اسکن لینک..."
    )

    try:

        # اجرای اسکن در Thread جدا
        stats, error = await asyncio.to_thread(
            scan_url_request,
            url
        )

        # اگر خطا
        if error:

            await update.message.reply_text(
                error
            )

            return

        # ساخت نتیجه
        message = make_result(
            stats
        )

        # ارسال نتیجه
        await update.message.reply_text(
            message
        )

    except Exception as error:

        print(
            f"URL scan error: {error}"
        )

        await update.message.reply_text(
            "خطایی هنگام اسکن لینک رخ داد."
        )


# ============================================================
# آماده‌سازی Telegram Bot
# ============================================================

async def setup_telegram():

    global telegram_app

    global telegram_loop

    # گرفتن Event Loop فعلی
    telegram_loop = asyncio.get_running_loop()

    print(
        "Creating Telegram application..."
    )

    # ساخت Application
    telegram_app = (
        Application
        .builder()
        .token(BOT_TOKEN)
        .build()
    )

    # ========================================================
    # ثبت Handler دستور /start
    # ========================================================

    telegram_app.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    # ========================================================
    # ثبت Handler فایل
    # ========================================================

    telegram_app.add_handler(
        MessageHandler(
            filters.Document.ALL,
            scan_file_handler
        )
    )

    # ========================================================
    # ثبت Handler پیام متنی
    # ========================================================

    telegram_app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            scan_url_handler
        )
    )

    # ========================================================
    # آماده‌سازی Application
    # ========================================================

    await telegram_app.initialize()

    # شروع Application
    await telegram_app.start()

    # ========================================================
    # تنظیم Webhook
    # ========================================================

    if not WEBHOOK_URL:

        print(
            "ERROR: WEBHOOK_URL is not configured."
        )

        return

    print(
        f"Setting Telegram webhook: "
        f"{WEBHOOK_URL}"
    )

    await telegram_app.bot.set_webhook(
        url=WEBHOOK_URL,
        drop_pending_updates=True
    )

    print(
        "King Scanner Bot started."
    )

    print(
        "Webhook is active."
    )


# ============================================================
# اجرای Event Loop ربات
# ============================================================

def run_telegram():

    try:

        # asyncio را برای Telegram اجرا می‌کنیم
        asyncio.run(
            setup_telegram()
        )

    except Exception as error:

        print(
            f"Telegram startup error: {error}"
        )


# ============================================================
# اجرای اصلی برنامه
# ============================================================

def main():

    # ========================================================
    # بررسی BOT_TOKEN
    # ========================================================

    if not BOT_TOKEN:

        raise ValueError(
            "BOT_TOKEN environment variable is not set."
        )

    # ========================================================
    # بررسی VirusTotal API Key
    # ========================================================

    if not VT_API_KEY:

        raise ValueError(
            "VT_API_KEY environment variable is not set."
        )

    # ========================================================
    # بررسی Webhook URL
    # ========================================================

    if not WEBHOOK_URL:

        print(
            "WARNING: WEBHOOK_URL is not set."
        )

        print(
            "Set RENDER_EXTERNAL_URL or WEBHOOK_URL."
        )

    # ========================================================
    # اجرای Telegram در Thread جدا
    # ========================================================

    from threading import Thread

    telegram_thread = Thread(
        target=run_telegram,
        daemon=True
    )

    telegram_thread.start()

    # ========================================================
    # اجرای Flask
    # ========================================================

    run_web()


# ============================================================
# شروع برنامه
# ============================================================

if __name__ == "__main__":

    main()
