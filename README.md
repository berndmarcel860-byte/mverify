# MVerify - Email Verification Tool

A powerful email verification tool that helps reduce bounce rates before sending email campaigns. MVerify checks if emails are valid and safe to send, classifying them into different risk levels.

## Features

- ✅ **Single Email Verification** - Verify individual email addresses quickly
- 📋 **Bulk Verification** - Enter multiple emails manually (one per line)
- 📁 **CSV Upload** - Upload and verify large email lists from CSV files
- 🎯 **Risk Classification** - Emails are classified into four categories:
  - **Valid**: Emails with proper MX configuration and no risk indicators
  - **Low Risk**: Valid emails with single MX record
  - **Medium Risk**: Disposable emails or suspicious patterns
  - **Invalid**: Invalid syntax, non-existent domains, or no mail servers
- 💾 **CSV Export** - Export verification results for further analysis
- ⚡ **Real-time DNS/MX Verification** - Checks domain DNS and MX records
- 🛡️ **Disposable Email Detection** - Identifies temporary/throwaway email services
- 🔍 **Pattern Analysis** - Detects suspicious email patterns

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/berndmarcel860-byte/mverify.git
cd mverify
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Application

**Development Mode:**
```bash
python app.py
```

**Development with Debug Mode (not recommended for production):**
```bash
DEBUG=true python app.py
```

The application will start on `http://localhost:5000`

**Production Deployment:**
For production use, it's recommended to use a production WSGI server like Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Web Interface

1. Open your browser and navigate to `http://localhost:5000`
2. Choose your verification method:
   - **Single Email**: Enter one email address and click "Verify Email"
   - **Multiple Emails**: Enter multiple emails (one per line) and click "Verify All Emails"
   - **CSV Upload**: Upload a CSV file containing email addresses

### CSV File Format

Your CSV file should contain email addresses in one column. The tool automatically detects columns named:
- `email`
- `email address`
- `e-mail`
- `mail`

Example CSV:
```csv
email
john@example.com
jane@company.org
test@tempmail.com
```

If no header is found, the first column is used by default.

### Exporting Results

After verification, click the "Export as CSV" button to download results including:
- Email address
- Status (valid/invalid)
- Risk level
- Details about the verification
- Timestamp

## Risk Level Classification

### Valid ✅
- Proper email syntax
- Domain exists with multiple MX records
- No suspicious patterns
- Not a disposable email service
- **Note**: For major providers (Gmail, Outlook, etc.), mailbox verification is blocked, so only domain-level checks are performed

### Low Risk ⚠️
- Valid email format
- Domain exists with single MX record
- May have minimal configuration
- Mailbox verification unavailable (most providers block this)

### Medium Risk 🟠
- Disposable/temporary email services (e.g., tempmail.com, 10minutemail.com)
- Suspicious patterns (e.g., test123@, noreply@)
- Valid syntax but potential deliverability issues

### Invalid ❌
- Invalid email syntax
- Non-existent domain
- No mail server configuration (no MX or A records)
- Cannot receive emails
- Mailbox verified as non-existent (when verification is available)

## Verification Limitations

**Important**: This tool verifies that email domains exist and can receive mail, but cannot guarantee that specific mailboxes exist at major providers like Gmail, Outlook, Yahoo, etc.

**What we verify:**
- ✅ Email syntax and format
- ✅ Domain existence (DNS)
- ✅ Mail server configuration (MX records)
- ✅ Disposable email detection
- ✅ Suspicious pattern detection
- ✅ SMTP mailbox verification (when available)

**What we cannot verify:**
- ❌ Whether a specific mailbox exists at Gmail, Outlook, Yahoo, etc. (these providers block verification to prevent spam)
- ❌ Whether the mailbox is active and monitored
- ❌ Whether emails will be accepted (inbox rules, spam filters, etc.)

**Best practice**: Use this tool to eliminate obviously invalid addresses (bad domains, typos, disposable emails) before sending campaigns. For major providers, the tool verifies the domain can receive mail but shows "mailbox unverified" to indicate the limitation.

## Technical Details

### Email Verification Process

1. **Syntax Validation**: Checks if the email follows RFC standards
2. **Format Validation**: Uses email-validator library for comprehensive format checking
3. **Disposable Detection**: Checks against known disposable email providers
4. **Pattern Analysis**: Identifies suspicious patterns (test accounts, no-reply addresses)
5. **DNS Lookup**: Verifies domain exists
6. **MX Record Check**: Confirms mail server configuration
7. **Risk Assessment**: Classifies based on all checks

### Technologies Used

- **Flask**: Web framework
- **dnspython**: DNS query functionality
- **email-validator**: Email format validation
- **HTML/CSS/JavaScript**: Frontend interface

## API Endpoints

### POST /verify/single
Verify a single email address.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "email": "user@example.com",
  "status": "valid",
  "risk_level": "Valid",
  "details": "Valid email with proper MX configuration",
  "timestamp": "2024-11-22 17:45:30"
}
```

### POST /verify/multiple
Verify multiple email addresses.

**Request:**
```json
{
  "emails": ["user1@example.com", "user2@example.com"]
}
```

**Response:**
```json
{
  "results": [
    {
      "email": "user1@example.com",
      "status": "valid",
      "risk_level": "Valid",
      "details": "Valid email with proper MX configuration",
      "timestamp": "2024-11-22 17:45:30"
    },
    ...
  ]
}
```

### POST /verify/csv
Upload and verify emails from CSV file.

**Request:** multipart/form-data with file

**Response:** Same as /verify/multiple

### POST /export/csv
Export verification results as CSV.

**Request:**
```json
{
  "results": [...]
}
```

**Response:** CSV file download

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.