import hashlib
import mimetypes
import os
import time
import requests
from urllib.parse import urlparse
import schedule
from telegram import ParseMode, Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
import threading
import csv
import requests
from io import StringIO

url_haus = "https://urlhaus.abuse.ch/downloads/csv_online/"
PDF_OUTPUT_PATH = 'output.pdf'
DOWNLOAD_PATH = 'files'
TOKEN_BOT = "6819616693:AAETPhZH6ZYc_8YPx7dKr0Cu1S-C8nLfd2s"
VT_API_KEY = "e1d043e21e12d4fab6574e99da8fec061a0615851544cbfc4e4ff9838500e7b4"
DOWNLOADS_DIR = "downloads"
TEMP_FILE_NAME = "temp_file"

def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text(
        'Hello there! 👋 I am your security assistant bot. 🛡️\n\n'
        'You can send me a URL or a document, and I will check it for any security threats. '
        'Just paste the URL or upload the file, and I will handle the rest. '
        'I will also provide you with a report on the security status of the URL or file. '
        'I am here to help you stay safe online. 🛡️'
    )

def check_host_in_csv(update, url, host_to_check):
    response = requests.get(url)
    if response.status_code == 200:
        file_content = StringIO(response.content.decode('utf-8'))
        csv_reader = csv.reader(file_content, delimiter=',')

        for row in csv_reader:
            if len(row) > 2 and host_to_check in row[2]:
                update.message.reply_text("⚠️ Security Warning ⚠️\nThis URL has been detected as a potential security risk based on information from URLHAUS. To safeguard your security, we recommend avoiding access to it at this time. Thank you for your understanding! 🛡️")

def is_url(user_input):
    try:
        result = urlparse(user_input)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def handle_input(update: Update, context: CallbackContext) -> None:
    user_input = update.message.text

    if is_url(user_input):
        handle_url(update, context, user_input)
    else:
        update.message.reply_text("⚠️ Ooops! ⚠️\nInvalid input. Please send a valid URL or a file. Make sure to double-check and try again. 🤖")
        
def handle_url(update: Update, context: CallbackContext, url: str) -> None:
    message = update.message.reply_text("🤖 Initiating URL checking process, please wait")
    message_id = message.message_id
    chat_id = message.chat_id

    for i in range(3):
        time.sleep(1)  # Menunggu selama satu detik
        new_text = f"🤖 Initiating URL checking process, please wait{'.' * (i + 1)}"
        context.bot.edit_message_text(
            text=new_text,
            chat_id=chat_id,
            message_id=message_id,
            parse_mode=ParseMode.MARKDOWN,  # Menggunakan ParseMode untuk memperbolehkan pemformatan Markdown
        )
    try:
        downloaded_file_path = download_file(url)
        convert_to_pdf(update, context, url)
        
        scan_url(update, context, url)
        
        handle_file_url(update, context, downloaded_file_path)
        
        check_host_in_csv(update, url_haus, url)
        
    except Exception as e:
        update.message.reply_text(f"⚠️ Ooops! ⚠️\nThere was an error processing the URL. Please make sure it's valid and try again. If the issue persists, feel free to contact support. Error details: {str(e)}")
        
def handle_file(update: Update, context: CallbackContext):
    file_id = update.message.document.file_id
    file = context.bot.get_file(file_id)

    temp_file_path = os.path.join(DOWNLOADS_DIR, TEMP_FILE_NAME).replace('\\', '/')
    file.download(temp_file_path)

    if not os.path.exists(temp_file_path):
        update.message.reply_text("⚠️ Ooops! ⚠️\nSomething went wrong while processing the file. Please check the file and try again. 🤖")
        return

    file_hash = calculate_sha256(temp_file_path)
    if file_hash is None:
        update.message.reply_text("⚠️ Ooops! ⚠️\nSomething went wrong while processing the file. Please check the file and try again. 🤖")
        os.remove(temp_file_path)
        return

    file_name = update.message.document.file_name
    file_type = update.message.document.mime_type

    reply_text = f"🔍 Analyzing File: {file_name}\n" \
                 f"📄 Type: {file_type}\n" \
                 f"🔑 SHA256 Hash: {file_hash}\n\n"

    extracted_file_path = os.path.join(DOWNLOADS_DIR, "full_sha256.txt")
    is_malware_local = search_sha256_in_file(file_hash, extracted_file_path)
    if is_malware_local:
        reply_text += '⚠️ Security Warning from MalwareBazaar ⚠️ \n' \
                    f'🔗 Full Report Link: [MalwareBazaar Report](https://bazaar.abuse.ch/sample/{file_hash}/)\n\n'
    else:
        reply_text += '✅ SAFE ✅\nFile is safe according to MalwareBazaar! No malicious detection by antivirus engines!\n'

    with open(temp_file_path, "rb") as file_content:
        files = {"file": ("temp_file", file_content)}
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        analysis_complete = False
        while not analysis_complete:
            analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            if analysis_response.status_code == 200:
                analysis_details = analysis_response.json()
                analysis_status = analysis_details.get('data', {}).get('attributes', {}).get('status', '')
                if analysis_status == 'completed':
                    analysis_complete = True
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=headers)
                    analysis_details = analysis_response.json()
                    
                    status_info = analysis_details.get('data', {}).get('attributes', {}).get('stats', {})
                    malicious_count = status_info.get("malicious", 0)
                    undetected_count = status_info.get("undetected", 0)
                    timeout_count = status_info.get("timeout", 0)
                    type_unsupported_count = status_info.get("type-unsupported", 0)

                    if malicious_count > 0:
                        reply_text += f'⚠️ Security Warning from VirusTotal! {malicious_count} out of {malicious_count + undetected_count + timeout_count + type_unsupported_count} antivirus engines detect this file as malicious. ⚠️\n' \
                                    f'\n🔗 Full Report Link: [VirusTotal Report](https://www.virustotal.com/gui/file/{file_hash})\n\n'
                    else:
                        reply_text += '✅ SAFE ✅\nFile is safe according to VirusTotal! No malicious detection by antivirus engines.\n'
            time.sleep(3)  # Delay untuk polling status
    update.message.reply_text(reply_text, parse_mode='Markdown')
    os.remove(temp_file_path)

    
def handle_file_url(update: Update, context: CallbackContext, file_path: str):
    file_hash = calculate_sha256(file_path)
    if file_hash is None:
        update.message.reply_text("Failed to calculate file hash.")
        return

    file_name = os.path.basename(file_path)
    file_type, _ = mimetypes.guess_type(file_name)
    reply_text = f"🔍 Analyzing File: {file_name}\n" \
                 f"📄 Type: {file_type}\n" \
                 f"🔑 SHA256 Hash: {file_hash}\n\n"

    extracted_file_path = os.path.join(DOWNLOADS_DIR, "full_sha256.txt")
    is_malware_local = search_sha256_in_file(file_hash, extracted_file_path)
    if is_malware_local:
        reply_text += '⚠️ Security Warning from MalwareBazaa r⚠️ \n' \
                    f'🔗 Full Report Link: [MalwareBazaar Report](https://bazaar.abuse.ch/sample/{file_hash}/)\n\n'

    with open(file_path, "rb") as file_content:
        files = {"file": (file_name, file_content)}
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)

    print(response.status_code)
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        analysis_complete = False
        while not analysis_complete:
            analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            if analysis_response.status_code == 200:
                analysis_details = analysis_response.json()
                analysis_status = analysis_details.get('data', {}).get('attributes', {}).get('status', '')
                if analysis_status == 'completed':
                    analysis_complete = True
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=headers)
                    analysis_details = analysis_response.json()
                    
                    status_info = analysis_details.get('data', {}).get('attributes', {}).get('stats', {})
                    malicious_count = status_info.get("malicious", 0)
                    undetected_count = status_info.get("undetected", 0)
                    timeout_count = status_info.get("timeout", 0)
                    type_unsupported_count = status_info.get("type-unsupported", 0)

                    if malicious_count > 0:
                        reply_text += f'⚠️ Security Warning from VirusTotal! {malicious_count} out of {malicious_count + undetected_count + timeout_count + type_unsupported_count} antivirus engines detect this file as malicious. ⚠️\n' \
                                    f'\n🔗 Full Report Link: [VirusTotal Report](https://www.virustotal.com/gui/file/{file_hash})\n\n'
                    else:
                        reply_text += '✅ SAFE ✅\nFile is safe according to VirusTotal! No malicious detection by antivirus engines.\n'
                time.sleep(3)

        try:
            update.message.reply_text(reply_text, parse_mode='Markdown')
            # Debug statement to confirm that the message is sent successfully
            print("Message sent successfully.")
        except Exception as e:
            print(f"Error sending updated message: {str(e)}")

    os.remove(file_path)

    
def download_file(url, base_path="downloads"):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)

        # Mendeteksi ekstensi file dari URL
        parsed_url = urlparse(url)
        file_name = os.path.basename(parsed_url.path)
        file_extension = os.path.splitext(file_name)[1]
        
        # Membuat direktori berdasarkan ekstensi file jika belum ada
        save_path = os.path.join(base_path, file_extension[1:])
        os.makedirs(save_path, exist_ok=True)

        # Menyimpan file
        save_path = os.path.join(save_path, file_name)
        with open(save_path, 'wb') as file:
            file.write(response.content)

        print(f"File berhasil diunduh dan disimpan di: {save_path}")
        return save_path
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Error: {err}")
    
def convert_to_pdf(update: Update, context: CallbackContext, url: str) -> None:
    try:
        headers = {
            'Content-Type': 'application/json',
            'X-RapidAPI-Key': '706c94aa4emsh061c964bba6e6cep1fdfd0jsn804a8a6bea8a',
            'X-RapidAPI-Host': 'pdf-generator9.p.rapidapi.com'
        }
        data = {'url': url}

        response = requests.post('https://pdf-generator9.p.rapidapi.com/pdfgenerator', headers=headers, json=data)
        response.raise_for_status()

        with open(PDF_OUTPUT_PATH, 'wb') as pdf_file:
            pdf_file.write(response.content)

        with open(PDF_OUTPUT_PATH, 'rb') as pdf_file:
            caption_text = f"{url} \nDetermine the website's reliability and trustworthiness."
            update.message.reply_document(pdf_file, caption=caption_text)

    except requests.exceptions.HTTPError as err:
        if err.response.status_code == 500:
            base_url = get_base_url(url)
            convert_to_pdf(update, context, base_url)
        else:
            base_url = get_base_url(url)
            convert_to_pdf(update, context, base_url)
    except Exception as e:
        print(f"Terjadi kesalahan saat mengkonversi URL ke PDF: {str(e)}")
    finally:
        if os.path.exists(PDF_OUTPUT_PATH):
            os.remove(PDF_OUTPUT_PATH)
            
def scan_url(update: Update, context: CallbackContext, url: str) -> None:
    # Send the URL for scanning to VirusTotal
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    # Check if the response status code is 200 (OK)
    if response.status_code == 200:
        result = response.json()

        # Extracting key details from the analysis result
        analysis_id = result['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_details = analysis_response.json()

        status_info = analysis_details.get('data', {}).get('attributes', {}).get('stats', {})

        # Correcting the undetected count location
        undetected_count = status_info.get("undetected", 0)
        malicious_count = status_info.get("malicious", 0)
        
        # Construct the message
        if malicious_count > 0:
            detection_message = f'⚠️ Security Warning! {malicious_count} out of {malicious_count + undetected_count} antivirus engines flag this URL as potentially harmful. Exercise caution when accessing it. ⚠️'
            api_url = 'https://api.api-ninjas.com/v1/urllookup?url={}'.format(url)
            
            # Try to send the API request multiple times if the status code is not 200
            for _ in range(3):
                api_response = requests.get(api_url, headers={'X-Api-Key': '7X396BVCpCV2A69CJtPWQg==XNWlXblyEWJ61IO0'})
                
                # Check if the API response status code is 200 (OK)
                if api_response.status_code == 200:
                    api_result = api_response.json()
                    country = api_result.get('country', 'Unknown')
                    isp = api_result.get('isp', 'Unknown')
                    detection_message += f'\n\n🌎 Country: {country}\n🌐 ISP: {isp}'
                    break  # Break the loop if successful
                else:
                    time.sleep(1)  # Sleep for 1 second before retrying

            else:
                detection_message += '\n\nUnable to retrieve additional information about the URL after multiple attempts.'

        else:
            detection_message = '✅ Safe URL ✅ \nNo malicious detection by the antivirus engine.'

        # Combine all parts of the message
        reply_text = f"{detection_message}\n\n"

        # Reply to the user
        update.message.reply_text(reply_text)

    else:
        update.message.reply_text(f"❌ Unable to process the URL. Received status code: {response.status_code}")

    
def handle_document(update: Update, context: CallbackContext):
    document = update.message.document
    file_id = document.file_id
    new_file = context.bot.get_file(file_id)
    file_path = os.path.join(DOWNLOAD_PATH, document.file_name)
    new_file.download(file_path)

    handle_file(update, context, file_path)

def get_base_url(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    return base_url

def search_sha256_in_file(hash_value, file_path):
    """Searches for a SHA256 hash in a text file."""
    with open(file_path, "r") as f:
        for line in f:
            if line.strip() == hash_value:
                return True
    return False

def calculate_sha256(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()

    # Check if file exists and print file path for debugging
    if not os.path.exists(file_path):
        print(f"File does not exist: {file_path}")
        return None

    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def download_and_extract_file():
    """Downloads and extracts the SHA256 file regularly."""
    url = "https://bazaar.abuse.ch/export/txt/sha256/full/"
    response = requests.get(url)

    if response.status_code == 200:
        zip_file_path = os.path.join(DOWNLOADS_DIR, "abuse_ch_full_sha256.zip")
        with open(zip_file_path, "wb") as f:
            f.write(response.content)

        import zipfile
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(DOWNLOADS_DIR)

        print("File downloaded and extracted successfully!")
    else:
        print(f"Error downloading file: {response.status_code}")

def job():
    print("Running download_and_extract_file job...")
    download_and_extract_file()

def main() -> None:
    updater = Updater(TOKEN_BOT, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_input))
    dispatcher.add_handler(MessageHandler(Filters.document, handle_file))
    
    # Start the polling loop in a separate thread
    polling_thread = threading.Thread(target=updater.start_polling, daemon=True)
    polling_thread.start()

    # Schedule the job in a separate thread
    job_thread = threading.Thread(target=job, daemon=True)
    job_thread.start()

    # Keep the main thread running
    updater.idle()

if __name__ == '__main__':
    main()