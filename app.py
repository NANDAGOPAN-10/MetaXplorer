import os
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

def get_clean_mime(filename):
    """Safely find file extensions natively without any external packages"""
    ext = os.path.splitext(filename)[1].lower()
    mime_types = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
        '.pdf': 'application/pdf', '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
        '.mp4': 'video/mp4', '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska'
    }
    return mime_types.get(ext, 'application/octet-stream')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file segment provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Null filename reference'}), 400

    try:
        file_bytes = file.read()
        file_size = len(file_bytes)
        
        # Calculate secure hashes natively
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        detected_mime = get_clean_mime(file.filename)

        report = {
            'summary': {
                'filename': file.filename,
                'mime_type': detected_mime,
                'size_bytes': file_size,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            },
            'hashes': {'md5': md5, 'sha1': sha1, 'sha256': sha256},
            'metadata': {
                'Status': 'File processed cleanly in cloud environment.'
            },
            'anomalies': []
        }

        return jsonify(report)

    except Exception as e:
        return jsonify({'error': f'Parsing failure: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
