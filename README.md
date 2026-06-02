# PaperTrail

A collaborative document review and approval platform for teams.

Upload contracts, proposals, and policies. Collect comments and get sign-off — all in one place.

## Features

- Create and manage documents with public/private visibility
- Comment threads on each document
- File attachments
- Status workflow: Draft → In Review → Approved / Rejected
- URL preview for linked resources
- Role-based access (member / admin)

## Getting started

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open [http://localhost:5000](http://localhost:5000).

A default admin account and sample documents are created on first run.

## Tech stack

- Python / Flask
- SQLite
- Bootstrap 5
- Jinja2

## Project structure

```
papertrail/
├── app.py          # Routes and application logic
├── database.py     # Schema and seed data
├── requirements.txt
├── static/         # CSS and JS
├── templates/      # Jinja2 templates
└── uploads/        # Uploaded attachments
```
