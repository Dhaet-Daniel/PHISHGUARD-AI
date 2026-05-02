import requests
import json

# Test structured email
payload = {
    'subject': 'Host Your Own Hackathon on Kaggle Now!',
    'sender_info': {
        'email': 'no-reply@kaggle.com',
        'display_name': 'Kaggle',
        'reply_to': 'no-reply@kaggle.com',
        'return_path': 'bounce@kaggle.com',
    },
    'body_text': 'Hi Daniel Kapolobwe, Community Hackathons are now available to all Kaggle users. Learn more at https://www.kaggle.com/.',
    'body_html': '<html><body><p>Hi Daniel Kapolobwe, Community Hackathons are now available to all Kaggle users.</p><a href="https://www.kaggle.com/">Learn more</a></body></html>',
    'headers': {
        'Authentication-Results': 'spf=pass; dkim=pass; dmarc=pass',
        'Received': 'from mail.kaggle.com by mx.google.com',
        'Reply-To': 'no-reply@kaggle.com',
        'Return-Path': '<bounce@kaggle.com>',
    },
    'links': [
        {'text': 'Learn more', 'url': 'https://www.kaggle.com/', 'source': 'html'}
    ],
    'attachments': []
}

response = requests.post('http://localhost:8000/api/v1/predict', json=payload)
print('Structured Email Test:')
print('Status:', response.status_code)
print('Prediction:', response.json().get('prediction'))
print('Category:', response.json().get('category'))
print('Risk Level:', response.json().get('risk_level'))
print()

# Test raw email
raw_payload = {
    'raw_email': '''From: Security Team <security-team@safe-payments-alert.com>
Reply-To: support@credential-check.xyz
Return-Path: <mailer@credential-check.xyz>
Subject: Urgent: Verify your payroll account
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain; charset=utf-8

Click here immediately to avoid account suspension. 
Reset your password now at http://bit.ly/payroll-reset'''
}

response2 = requests.post('http://localhost:8000/api/v1/predict', json=raw_payload)
print('Raw Email Test:')
print('Status:', response2.status_code)
print('Prediction:', response2.json().get('prediction'))
print('Category:', response2.json().get('category'))
print('Risk Level:', response2.json().get('risk_level'))
print()

# Test batch
batch_payload = [payload, raw_payload]

response3 = requests.post('http://localhost:8000/api/v1/batch-predict', json=batch_payload)
print('Batch Test:')
print('Status:', response3.status_code)
results = response3.json()
print('Number of results:', len(results))
for i, result in enumerate(results):
    print(f'Result {i+1}: Prediction={result.get("prediction")}, Category={result.get("category")}, Risk Level={result.get("risk_level")}')