from flask import Flask, render_template, request, redirect, url_for, send_file, Response
import os
import time
import zipfile
import glob
from werkzeug.utils import secure_filename
from hybrid_tool import HybridXSSDetectionTool
import progress_tracker

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def extract_zip_to_directory(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def get_latest_file(pattern):
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getctime)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        progress_tracker.clear_messages()  # Reset progress messages for a new scan
        mode = request.form['mode']
        target_url = request.form.get('target_url')
        uploaded_file = request.files.get('source_code')
        code_directory = None

        if uploaded_file and uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(filepath)

            if filename.endswith('.zip'):
                code_directory = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted')
                os.makedirs(code_directory, exist_ok=True)
                extract_zip_to_directory(filepath, code_directory)
            elif filename.endswith('.py'):
                code_directory = app.config['UPLOAD_FOLDER']

        if mode == 'sast' or mode == 'hybrid':
            if code_directory:
                hybrid_tool = HybridXSSDetectionTool(mode, code_directory=code_directory)
                hybrid_tool.run()

        if mode == 'dast' or mode == 'hybrid':
            if target_url:
                hybrid_tool = HybridXSSDetectionTool(mode, target_url=target_url, code_directory=code_directory)
                hybrid_tool.run()

        # Redirect to the report download page
        return redirect(url_for('download_report', mode=mode))

    return render_template('index.html')

@app.route('/download')
def download_report():
    mode = request.args.get('mode')
    if mode == 'sast':
        file_path = get_latest_file('sast_results*.csv')
    elif mode == 'dast':
        file_path = get_latest_file('dast_results*.csv')
    elif mode == 'hybrid':
        file_path = get_latest_file('hybrid_results*.csv')
    else:
        return "Invalid mode selected.", 400

    if file_path:
        return send_file(file_path, as_attachment=True)
    else:
        return "No report available.", 404

@app.route('/download_crawled_urls')
def download_crawled_urls():
    file_path = get_latest_file('crawled_urls*.csv')
    if file_path:
        return send_file(file_path, as_attachment=True)
    else:
        return "No crawled URLs report available.", 404

@app.route('/progress')
def progress():
    def generate():
        while True:
            messages = progress_tracker.get_messages()
            if messages:
                message = messages.pop(0)
                yield f"data:{message}\n\n"
            else:
                time.sleep(0.5)
    return Response(generate(), mimetype='text/event-stream')

if __name__ == "__main__":
    app.run(debug=True)
