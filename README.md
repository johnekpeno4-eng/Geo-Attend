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
- ESP-12F + R307 attendance over a device-key authenticated API.
- Offline device check-ins and phone check-in through the ESP access point.

## Tech Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Node.js
- Database: SQLite 3
- Email: Nodemailer SMTP

## Project Structure

```text
.
├── server.js                 # Node.js server and API routes
├── backend/                  # Server-side feature modules
├── public/
│   ├── pages/auth/            # Login, registration, password reset
│   ├── pages/admin/           # Admin dashboards and management pages
│   ├── pages/student/         # Student pages
│   ├── pages/security/        # Security information page
│   └── assets/                # Shared CSS and JavaScript
├── src/                       # ESP firmware source
├── include/                   # Firmware headers and config template
├── firmware/archive/          # Inactive legacy firmware
├── scripts/                   # Local maintenance and startup scripts
├── fingerprint-matcher/       # Optional loopback fingerprint matcher
├── tools/                      # Local development tools
├── data/                       # Ignored database, reports, and logs
├── .env                       # Private runtime secrets (ignored by Git)
└── .env.example               # Safe placeholders only
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

Keep all server secrets and service credentials in the ignored `.env` file. The committed `.env.example` contains placeholders only. Set `DEVICE_TOKEN_SECRET` and `ADMIN_JWT_SECRET` to separate random values of at least 32 characters. Generate each with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Keep secrets stable across restarts and never commit `.env` or per-device credentials. An ESP must still receive its device API key and network configuration before firmware is flashed; these values are device-specific.

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

## ESP fingerprint attendance setup

This workspace uses its existing Node.js and SQLite backend rather than adding a separate Python database. Attendance records are stored on the server. The ESP stores its R307 templates and a bounded LittleFS queue of attendance events while offline. The server stores only each device's API-key hash and the student-to-slot mapping. The R307 template is not uploaded and no raw fingerprint image is stored. Existing camera fingerprint templates use AES-GCM encryption with `FINGERPRINT_TEMPLATE_KEY`.

1. Install PlatformIO Core and the ESP8266 platform. From the workspace root, run `pio pkg install` to fetch the dependencies in `platformio.ini`.
2. Provision each ESP with a unique `DEVICE_ID`, server URL, router credentials, student AP credentials, the shared token secret from `.env`, its one-time device API key, and the PEM root certificate that validates your server. The private `include/device_config.h` is ignored by Git; `include/device_config.h.example` is a template only. Keep certificate validation enabled in production; `SERVER_TLS_INSECURE` is only for local development.
3. Start GeoAttend with `npm.cmd start`, sign in as Overall Admin, and open **Fingerprint Devices**. Register the ESP ID and copy its one-time API key into the private device configuration.
4. Wire R307 TX to GPIO4 and RX to GPIO5 at 57600 baud; buzzer to GPIO13; green LED to GPIO16; active-low red LED to GPIO2. Optional OLED and DS3231 share SDA GPIO12 and SCL GPIO14. Make sure external circuits do not hold boot-strapping pins at the wrong level.
5. Flash with `pio run -t upload`. ESP8266 AP+STA uses one radio, so after the station joins a router the AP follows that router's Wi-Fi channel. The student AP is configured for up to four clients.
6. In Fingerprint Devices, queue an enrollment for a student. The ESP polls for requests; have the student place and remove the same finger when prompted. Sensor slot IDs are allocated from 1 through 127.
7. Create a lecture session while the ESP can reach the server so it can cache the active session. Students join the ESP Wi-Fi and open `http://192.168.4.1/`. This lightweight portal is stored in firmware, uses no external assets, and shows session, reader, network, and queued-check-in status. Students check in by scanning an enrolled finger on the R307 reader; the ESP queues the event in LittleFS while the server is offline and uploads it after connectivity returns.

NTP provides UTC time. A DS3231 is used as fallback after it has been synchronized from NTP; a reset or unsynchronized RTC does not produce check-in timestamps. Offline check-ins upload in order and are deduplicated by session and student. The LittleFS queue is limited to 4 KB; explicitly rejected events are removed after the server logs them. Deleting biometric data removes server mappings immediately and queues a sensor template deletion for the next device connection.

## Device workflow verification plan

- Server: verify device creation stores only an API-key hash; reject a bad key and unknown slot; accept a valid scan in the session window; report a repeat scan as duplicate; reject an out-of-window scan and confirm it is logged.
- Enrollment: queue a student, complete two finger placements, confirm the slot mapping, delete the student's biometric data, and confirm the sensor clears its template after reconnecting.
- Hardware: sensor missing, enrollment, accepted/duplicate/rejected LED and buzzer patterns, router outage and queue recovery, restart while events are queued, NTP failure with a synchronized RTC, and router channel change.
- Offline portal: with mobile data disabled, join the device AP, open `http://192.168.4.1/`, verify the page and live status load, scan a finger without internet, confirm the queue count increases, then restore internet and confirm queued events sync.

R307 template capacity varies by module firmware; this setup caps allocation at 127 slots. ESP8266 has limited RAM and only a few stable AP clients, and it has no secure element. Use validated HTTPS in production and a dedicated access point or multiple ESP units for larger lectures. Calibrate the exact reader and timing setup before production use.

## Biometric retention and deletion

Fingerprint data is sensitive personal data under the Nigeria Data Protection Act, 2023. Before collecting it, the university should document the lawful basis, purpose, access roles, retention period, and student notice. This implementation does not set an automatic attendance-retention period; the university must establish and publish one before production use. Attendance exports and backups also need to follow that schedule.

R307 templates stay on the sensor; the ESP queues only slot/session/time events while offline. Browser fingerprint templates are AES-GCM encrypted with `FINGERPRINT_TEMPLATE_KEY`, and raw fingerprint images are not retained. An Overall Admin can use **Delete data** on the Fingerprint Devices page to erase the student's encrypted browser template, passkey credentials, phone binding, slot mappings, and pending enrollment; online ESPs receive a command to erase matching sensor slots. Backups are separate copies and must also be removed under the institution's retention policy. Review the official [Nigeria Data Protection Act, 2023](https://ndpc.gov.ng/wp-content/uploads/2024/03/Nigeria_Data_Protection_Act_2023.pdf) and obtain the university's privacy/compliance approval before deployment.

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

For real public use, deploy GeoAttend to a VPS or cloud server, connect a domain, and enable HTTPS/SSL for secure browser and biometric-related flows.

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
