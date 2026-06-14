import os
import hashlib
import datetime
from flask import Flask, render_template, request, jsonify, send_file
import io
import csv

# Metadata Extraction Libraries
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
from mutagen import File as MutagenFile
from hachoir.parser import createParser
from hachoir.metadata import extractMetadata
from hachoir.core import config as hachoir_config

# Disable Hachoir terminal warnings noise
hachoir_config.quiet = True

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB Upload Limit

def calculate_hashes(file_bytes):
    """Generates MD5, SHA-1, and SHA-256 hashes for data integrity."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }

def get_decimal_from_dms(dms, ref):
    """Converts Degrees, Minutes, Seconds (DMS) to Decimal Degrees."""
    if not dms:
        return None
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
    except (TypeError, IndexError):
        return None

    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

def extract_image_metadata(file_bytes):
    """Extracts EXIF and GPS Data from Images using Pillow."""
    metadata = {}
    gps_data = {}
    try:
        img = Image.open(io.BytesIO(file_bytes))
        exif = img._getexif()
        if exif:
            for tag, value in exif.items():
                decoded = TAGS.get(tag, tag)
                if decoded == "GPSInfo":
                    for t in value:
                        sub_decoded = GPSTAGS.get(t, t)
                        gps_data[sub_decoded] = value[t]
                else:
                    if isinstance(value, bytes):
                        try: value = value.decode('utf-8', errors='ignore')
                        except: value = str(value)
                    metadata[str(decoded)] = str(value)
            
            lat_dms = gps_data.get('GPSLatitude')
            lat_ref = gps_data.get('GPSLatitudeRef')
            lon_dms = gps_data.get('GPSLongitude')
            lon_ref = gps_data.get('GPSLongitudeRef')
            
            if lat_dms and lat_ref and lon_dms and lon_ref:
                metadata['computed_latitude'] = get_decimal_from_dms(lat_dms, lat_ref)
                metadata['computed_longitude'] = get_decimal_from_dms(lon_dms, lon_ref)
    except Exception as e:
        metadata['Error'] = f"Failed to parse image EXIF: {str(e)}"
    return metadata

def extract_pdf_metadata(file_bytes):
    """Extracts Metadata from PDFs using PyPDF2."""
    metadata = {}
    try:
        pdf = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        doc_info = pdf.metadata
        if doc_info:
            for key, val in doc_info.items():
                clean_key = key.strip('/')
                metadata[clean_key] = str(val)
    except Exception as e:
        metadata['Error'] = f"Failed to parse PDF metadata: {str(e)}"
    return metadata

def extract_audio_metadata(file_bytes, filename):
    """Extracts Audio Metadata using Mutagen."""
    metadata = {}
    try:
        temp_path = os.path.join("/tmp", filename) if os.path.exists("/tmp") else filename
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
        audio = MutagenFile(temp_path)
        if audio:
            for key, val in audio.items():
                metadata[str(key)] = str(val)
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except Exception as e:
        metadata['Error'] = f"Failed to parse Audio metadata: {str(e)}"
    return metadata

def extract_video_metadata(file_bytes, filename):
    """Extracts Video Metadata using Hachoir."""
    metadata = {}
    try:
        temp_path = os.path.join("/tmp", filename) if os.path.exists("/tmp") else filename
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
        parser = createParser(temp_path)
        if parser:
            with parser:
                hachoir_meta = extractMetadata(parser)
                if hachoir_meta:
                    for line in hachoir_meta.exportPlaintext():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            metadata[k.strip()] = v.strip()
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except Exception as e:
        metadata['Error'] = f"Failed to parse Video metadata: {str(e)}"
    return metadata

def run_anomaly_detection(metadata, mime_type):
    """Detects missing or suspicious tracking fields."""
    anomalies = []
    if not metadata or len(metadata) <= 2:
        anomalies.append("Suspiciously sparse metadata. Potential anti-forensics stripping detected.")
    if "image" in mime_type:
        if "Software" in metadata:
            anomalies.append(f"File edited/saved using external software: {metadata['Software']}")
        if "DateTime" not in metadata and "DateTimeOriginal" not in metadata:
            anomalies.append("Missing creation timestamp matching camera hardware signature.")
    if "pdf" in mime_type:
        if "Producer" in metadata and "Producer" in ["Unknown", "", "None"]:
            anomalies.append("Anonymized or missing PDF Producer application data.")
    return anomalies

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    filename = uploaded_file.filename
    file_bytes = uploaded_file.read()
    file_size = len(file_bytes)
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    image_exts = ['jpg', 'jpeg', 'png', 'tiff', 'webp']
    audio_exts = ['mp3', 'wav', 'flac', 'ogg', 'm4a']
    video_exts = ['mp4', 'mkv', 'avi', 'mov']
    
    if ext in image_exts: mime = f"image/{ext}"
    elif ext == 'pdf': mime = "application/pdf"
    elif ext in audio_exts: mime = f"audio/{ext}"
    elif ext in video_exts: mime = f"video/{ext}"
    else: mime = "application/octet-stream"

    hashes = calculate_hashes(file_bytes)
    extracted_meta = {}
    
    if ext in image_exts: extracted_meta = extract_image_metadata(file_bytes)
    elif ext == 'pdf': extracted_meta = extract_pdf_metadata(file_bytes)
    elif ext in audio_exts: extracted_meta = extract_audio_metadata(file_bytes, filename)
    elif ext in video_exts: extracted_meta = extract_video_metadata(file_bytes, filename)

    anomalies = run_anomaly_detection(extracted_meta, mime)
    
    report = {
        "summary": {
            "filename": filename,
            "size_bytes": file_size,
            "mime_type": mime,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        },
        "hashes": hashes,
        "metadata": extracted_meta,
        "anomalies": anomalies
    }
    return jsonify(report)

@app.route('/export/csv', methods=['POST'])
def export_csv():
    data = request.json
    if not data: return "No data provided", 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["FORENSIC METADATA ANALYSIS REPORT"])
    writer.writerow(["Generated At", data.get('summary', {}).get('timestamp')])
    writer.writerow([])
    writer.writerow(["FILE DETAILS"])
    for k, v in data.get('summary', {}).items(): writer.writerow([k, v])
    writer.writerow([])
    writer.writerow(["INTEGRITY HASHES"])
    for k, v in data.get('hashes', {}).items(): writer.writerow([k.upper(), v])
    writer.writerow([])
    writer.writerow(["EXTRACTED METADATA"])
    for k, v in data.get('metadata', {}).items():
        if k not in ['computed_latitude', 'computed_longitude']: writer.writerow([k, v])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype="text/csv", as_attachment=True, download_name="forensic_report.csv")

if __name__ == '__main__':
    app.run(debug=True, port=5000)