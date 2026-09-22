# GeoAttend

GeoAttend is a web-based attendance management system for institution/class attendance. It supports student registration, admin-managed class sessions, live check-ins, report generation, saved attendance PDFs, and local SQLite storage.

## Main Features

- Student registration with name, registration number, email, password, and profile details.
- Email OTP verification during registration/password reset.
- Student attendance check-in for active class sessions.
- Admin dashboard for creating sessions and monitoring live attendance.
- Department/level scoping for admins and sessions.
- Records page with generated attendance reports.
- PDF and CSV attendance export.
- Saved PDF reports for completed sessions.
- Student profile editing and signature capture.
- SQLite database storage.
- Mobile-friendly admin and student views.

## Tech Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Node.js
- Database: SQLite 3
- Email: Nodemailer SMTP

## Project Structure

```text
.
├── server.js                 # Node.js server and API routes
├── package.json              # Project scripts and dependencies
├── login.html                # Login page
├── register.html             # Student registration page
├── dashboard.html            # Admin dashboard
├── create-session.html       # Admin session creation
├── live-monitor.html         # Live attendance monitoring
├── records.html              # Attendance records and reports
├── students.html             # Registered students/admin-assisted check-in
├── admin-management.html     # Admin role/scope management
├── role-access.js            # Shared auth, role, UI, and API logic
├── mobile-admin.css          # Admin mobile styles
├── mobile-student.css        # Student mobile styles
└── data/                     # Local runtime database/reports, ignored by Git
```

## Requirements

Install these before running the project:

- Node.js
- npm
- Git

Check installation:

```powershell
node -v
npm.cmd -v
git --version
```

On Windows PowerShell, use `npm.cmd` if `npm` is blocked by execution policy.

## Installation

Clone the repository:

```powershell
git clone https://github.com/johnekpeno4-eng/Geo-Attend.git
cd Geo-Attend
```

Install dependencies:

```powershell
npm.cmd install
```

## Environment Setup

Create a `.env` file in the project root. Do not commit this file.

Example:

```env
PORT=4000
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-character-gmail-app-password
MAIL_FROM="GeoAttend <your-email@gmail.com>"
# SMTP_FROM is also accepted for compatibility
```

For Gmail, use a 16-character App Password, not your normal Gmail password.

The real `.env` file is ignored by Git to protect passwords and private configuration.

## Run Locally

Start the server:

```powershell
npm.cmd start
```

Open the website in your browser:

```text
http://localhost:4000/login.html
```

If port `4000` is already in use, either stop the old Node process or change `PORT` in `.env`.

## Database

GeoAttend uses SQLite.

The local database is stored inside:

```text
data/geoattend.db
```

This file is ignored by Git because it contains real student/admin/session data.

For safety, back up the `data/` folder regularly, especially before deployment or major updates.

## Git Safety

These files/folders are intentionally ignored:

- `.env`
- `node_modules/`
- `data/`
- SQLite database files
- logs
- generated PDFs/CSVs
- temporary files

Before pushing changes, check:

```powershell
git status
```

Make sure `.env`, database files, reports, and logs are not staged.

## Common Commands

Start server:

```powershell
npm.cmd start
```

Check Git status:

```powershell
git status
```

Commit changes:

```powershell
git add .
git commit -m "Describe your change"
```

Push to GitHub:

```powershell
git push
```

## Deployment Notes

Localhost only works while the computer running the server is on.

For real public use, deploy GeoAttend to a VPS or cloud server, connect a domain, and enable HTTPS/SSL. HTTPS is important for browser features such as geolocation and biometric-related flows.

A production deployment should include:

- VPS or cloud hosting
- Domain name
- SSL certificate
- Database backups
- Strong admin passwords
- Rate limiting for login/OTP routes
- Regular updates and monitoring

## Important Security Notes

- Never commit `.env`.
- Never commit `data/geoattend.db`.
- Never commit generated attendance PDFs containing student data.
- Use HTTPS in production.
- Use strong SMTP credentials or app passwords.
- Keep regular backups of database and reports.

## Repository

GitHub repository:

```text
https://github.com/johnekpeno4-eng/Geo-Attend
```
