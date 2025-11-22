"""
Email Verification Tool - Main Application
Verifies email addresses and classifies them by risk level
"""

from flask import Flask, render_template, request, jsonify, send_file
import csv
import io
import os
from datetime import datetime
from email_verifier import EmailVerifier

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

verifier = EmailVerifier()


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


@app.route('/verify/single', methods=['POST'])
def verify_single():
    """Verify a single email address"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email address is required'}), 400
    
    result = verifier.verify_email(email)
    return jsonify(result)


@app.route('/verify/multiple', methods=['POST'])
def verify_multiple():
    """Verify multiple email addresses"""
    data = request.get_json()
    emails = data.get('emails', [])
    
    if not emails:
        return jsonify({'error': 'At least one email address is required'}), 400
    
    results = []
    for email in emails:
        email = email.strip()
        if email:
            result = verifier.verify_email(email)
            results.append(result)
    
    return jsonify({'results': results})


@app.route('/verify/csv', methods=['POST'])
def verify_csv():
    """Verify emails from CSV upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'File must be a CSV'}), 400
    
    try:
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.reader(stream)
        
        results = []
        email_column = None
        
        for row_idx, row in enumerate(csv_reader):
            if row_idx == 0:
                # Try to find email column
                for idx, header in enumerate(row):
                    if header.lower() in ['email', 'email address', 'e-mail', 'mail']:
                        email_column = idx
                        break
                
                # If no header found, assume first column
                if email_column is None and row and '@' in row[0]:
                    email_column = 0
                    # Process this row as data
                    email = row[email_column].strip()
                    if email:
                        result = verifier.verify_email(email)
                        results.append(result)
                continue
            
            if email_column is not None and len(row) > email_column:
                email = row[email_column].strip()
                if email:
                    result = verifier.verify_email(email)
                    results.append(result)
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': f'Error processing CSV: {str(e)}'}), 500


@app.route('/export/csv', methods=['POST'])
def export_csv():
    """Export verification results as CSV"""
    data = request.get_json()
    results = data.get('results', [])
    
    if not results:
        return jsonify({'error': 'No results to export'}), 400
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Email', 'Status', 'Risk Level', 'Details', 'Verification Time'])
    
    # Write data
    for result in results:
        writer.writerow([
            result.get('email', ''),
            result.get('status', ''),
            result.get('risk_level', ''),
            result.get('details', ''),
            result.get('timestamp', '')
        ])
    
    # Convert to bytes
    output.seek(0)
    
    # Create response
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'email_verification_{timestamp}.csv'
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    # Debug mode should be disabled in production
    # Set DEBUG environment variable to 'true' to enable debug mode
    import os
    debug_mode = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)