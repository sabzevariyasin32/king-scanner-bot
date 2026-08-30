import os
import time
import asyncio
import hashlib
import base64
import requests

from flask import Flask
from threading import Thread

from telegram import Update
from telegram.ext import Application, MessageHandler, filters, CommandHandler

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

MAX_SCAN_WAIT = 120
SCAN_INTERVAL = 3

web_app = Flask(**name**)

@web_app.route("/")
def home():
return "King Scanner Bot is running."

def run_web():
port = int(os.environ.get("PORT", 10000))
web_app.run(host="0.0.0.0", port=port)

def get_headers():
return {
"x-apikey": VT_API_KEY
}

def get_file_report(file_hash):
try:
return requests.get(
f"{VT_BASE_URL}/files/{file_hash}",
headers=get_headers(),
timeout=15
)
except requests.RequestException:
return None

def upload_file(file_path):
try:
with open(file_path, "rb") as file:
return requests.post(
f"{VT_BASE_URL}/files",
files={"file": file},
headers=get_headers(),
timeout=60
)
except requests.RequestException:
return None

def get_analysis(analysis_id):
try:
return requests.get(
f"{VT_BASE_URL}/analyses/{analysis_id}",
headers=get_headers(),
timeout=15
)
except requests.RequestException:
return None

def wait_for_analysis(analysis_id):
start = time.time()

```
while time.time() - start < MAX_SCAN_WAIT:
    response = get_analysis(analysis_id)

    if response is None:
        return None, "ارتباط با VirusTotal برقرار نشد."

    if response.status_code != 200:
        return None, "خطا در دریافت وضعیت اسکن."

    attributes = response.json().get(
        "data", {}
    ).get(
        "attributes", {}
    )

    if attributes.get("status") == "completed":
        return attributes.get("stats", {}), None

    time.sleep(SCAN_INTERVAL)

return None, "زمان اسکن بیش از حد طولانی شد."
```

def scan_file(file_path):
sha256 = hashlib.sha256()

```
with open(file_path, "rb") as file:
    while True:
        chunk = file.read(1024 * 1024)

        if not chunk:
            break

        sha256.update(chunk)

file_hash = sha256.hexdigest()

existing = get_file_report(file_hash)

if existing is not None and existing.status_code == 200:
    stats = existing.json().get(
        "data", {}
    ).get(
        "attributes", {}
    ).get(
        "last_analysis_stats", {}
    )

    if stats:
        return stats, None

response = upload_file(file_path)

if response is None:
    return None, "ارتباط با VirusTotal برقرار نشد."

if response.status_code not in (200, 201):
    return None, "خطا در ارسال فایل به VirusTotal."

analysis_id = response.json().get(
    "data", {}
).get(
    "id"
)

if not analysis_id:
    return None, "شناسه اسکن دریافت نشد."

return wait_for_analysis(analysis_id)
```

def scan_url_request(url):
url_id = base64.urlsafe_b64encode(
url.encode()
).decode().rstrip("=")

```
try:
    existing = requests.get(
        f"{VT_BASE_URL}/urls/{url_id}",
        headers=get_headers(),
        timeout=15
    )
except requests.RequestException:
    existing = None

if existing is not None and existing.status_code == 200:
    stats = existing.json().get(
        "data", {}
    ).get(
        "attributes", {}
    ).get(
        "last_analysis_stats", {}
    )

    if stats:
        return stats, None

try:
    response = requests.post(
        f"{VT_BASE_URL}/urls",
        data={
            "url": url
        },
        headers=get_headers(),
        timeout=20
    )
except requests.RequestException:
    return None, "ارتباط با VirusTotal برقرار نشد."

if response.status_code not in (200, 201):
    return None, "خطا در ارسال لینک به VirusTotal."

analysis_id = response.json().get(
    "data", {}
).get(
    "id"
)

if not analysis_id:
    return None, "شناسه اسکن لینک دریافت نشد."

return wait_for_analysis(analysis_id)
```

def result_text(stats, file_name=None):
malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)
harmless = stats.get("harmless", 0)
undetected = stats.get("undetected", 0)

```
if malicious > 0:
    result = "مخرب"
elif suspicious > 0:
    result = "مشکوک"
else:
    result = "سالم"

message = (
    f"نتیجه اسکن: {result}\n\n"
    f"مخرب: {malicious}\n"
    f"مشکوک: {suspicious}\n"
    f"سالم: {harmless}\n"
    f"شناسایی نشده: {undetected}"
)

if file_name:
    message += f"\n\nنام فایل: {file_name}"

return message
```

async def start(update: Update, context):
await update.message.reply_text(
"سلام به کینگ اسکنر خوش اومدی\n"
"فایل یا لینک مورد نظرتو بفرست تا اسکن کنم."
)

async def scan_file_handler(update: Update, context):
document = update.message.document
file_name = document.file_name

```
await update.message.reply_text(
    f"در حال اسکن {file_name}..."
)

file_path = None

try:
    file_obj = await document.get_file()

    os.makedirs(
        "download",
        exist_ok=True
    )

    safe_name = os.path.basename(
        file_name
    )

    file_path = os.path.join(
        "download",
        f"{int(time.time())}_{safe_name}"
    )

    await file_obj.download_to_drive(
        file_path
    )

    stats, error = await asyncio.to_thread(
        scan_file,
        file_path
    )

    if error:
        await update.message.reply_text(
            error
        )
        return

    await update.message.reply_text(
        result_text(
            stats,
            file_name
        )
    )

except Exception as error:
    print(error)

    await update.message.reply_text(
        "خطایی هنگام اسکن فایل رخ داد."
    )

finally:
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass
```

async def scan_url_handler(update: Update, context):
url = update.message.text.strip()

```
await update.message.reply_text(
    "در حال اسکن لینک..."
)

try:
    stats, error = await asyncio.to_thread(
        scan_url_request,
        url
    )

    if error:
        await update.message.reply_text(
            error
        )
        return

    await update.message.reply_text(
        result_text(stats)
    )

except Exception as error:
    print(error)

    await update.message.reply_text(
        "خطایی هنگام اسکن لینک رخ داد."
    )
```

def main():
if not BOT_TOKEN:
raise ValueError(
"BOT_TOKEN environment variable is not set."
)

```
if not VT_API_KEY:
    raise ValueError(
        "VT_API_KEY environment variable is not set."
    )

app = Application.builder().token(
    BOT_TOKEN
).build()

app.add_handler(
    CommandHandler(
        "start",
        start
    )
)

app.add_handler(
    MessageHandler(
        filters.Document.ALL,
        scan_file_handler
    )
)

app.add_handler(
    MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        scan_url_handler
    )
)

print("King Scanner Bot started.")

app.run_polling()
```

if **name** == "**main**":
Thread(
target=run_web,
daemon=True
).start()

```
main()
```
