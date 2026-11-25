# Email Analyzer

A small desktop app that checks emails for common phishing and impersonation
warning signs. It gives a risk score and a plain-language summary. It is a guide,
not a guarantee that an email is safe or dangerous.

## Run it

From the project root, run:

```powershell
cd .\email_analyzer
python .\app.py
```

The app needs Python 3.8+ and Tkinter. It does not need third-party packages.

## Use it

Enter the sender, then add a subject, message, or both. You can also add a
recipient and attachments. Choose English, Arabic, Spanish, or French from the
language menu before checking the email. The app uses built-in phrase checks for
the selected language; quoted evidence stays as it appeared in the email.

The window opens at a size suited to your screen and can be resized. Use
**Save Report** to save a text copy of the results.

## Files

- `email_analyzer/app.py` — the app window and controls
- `email_analyzer/analyzer.py` — the checks, language text, and report creation

The checks run locally. Results are based on common patterns and can miss new
scams or flag legitimate emails, so verify anything concerning through a known,
official contact method.
