import os
import requests
import json
import zipfile


API_KEY = '...'


ZIP_FILE = 'protected_archive.zip'
PASSWORD = 'netology'

# Путь к директории, куда распаковывать файлы
EXTRACTED_DIR = 'extracted_files'

# Создаем директорию, если она не существует
if not os.path.exists(EXTRACTED_DIR):
    os.makedirs(EXTRACTED_DIR)

# Распаковка архива
with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
    zip_ref.extractall(EXTRACTED_DIR, pwd=PASSWORD.encode('utf-8'))

#  Анализ файлов через VirusTotal API
def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    params = {'apikey': API_KEY}
    response = requests.post(url, files=files, params=params)
    return response.json()

# Список для хранения результатов сканирования
scan_results = []

# Сканируем каждый файл в директории
for root, dirs, files in os.walk(EXTRACTED_DIR):
    for file in files:
        file_path = os.path.join(root, file)
        print(f'Scanning file: {file_path}')
        result = scan_file(file_path)
        scan_results.append(result)

# Этап 3. Обработка результатов сканирования
def get_detection_results(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

# Собираем данные о детектировании угроз антивирусами
detection_results = []

for result in scan_results:
    resource = result['resource']
    print(f'Getting detection results for {resource}')
    detection_result = get_detection_results(resource)
    detection_results.append(detection_result)

# Этап 4. Подготовка отчета
# Выводим статистику результатов сканирования
for result in detection_results:
    if 'scans' in result:
        print('Antivirus detection results:')
        for antivirus, details in result['scans'].items():
            print(f'{antivirus}: {details["result"]}')

# Составляем отчет в формате JSON
report_data = {
    'scan_results': scan_results,
    'detection_results': detection_results
}

with open('report.json', 'w') as f:
    json.dump(report_data, f)

print('Report saved to report.json')
