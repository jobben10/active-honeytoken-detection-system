\# Active Honeytoken Detection System

[![Python Tests](https://github.com/jobben10/active-honeytoken-detection-system/actions/workflows/tests.yml/badge.svg)](https://github.com/jobben10/active-honeytoken-detection-system/actions/workflows/tests.yml)



A defensive cybersecurity platform for detecting potential unauthorized access to sensitive documents using document-based honeytokens, real-time event detection, risk scoring, alerting, threat intelligence, MITRE ATT\&CK mapping, audit logging, and a SOC-style monitoring dashboard.



\## Overview



The Active Honeytoken Detection System is designed to place trackable honeytokens inside documents that appear legitimate and sensitive.



When a honeytoken is accessed, the system can:



1\. Receive the trigger event.

2\. Record the source IP address and user-agent information.

3\. Calculate a risk score.

4\. Identify detection reasons.

5\. Enrich the source IP with intelligence.

6\. Map relevant activity to MITRE ATT\&CK techniques.

7\. Generate a security alert.

8\. Record the activity in the audit trail.

9\. Present the event and alert to security analysts through the dashboard.

10\. Send Telegram notifications when configured.



The project is intended for defensive cybersecurity research, security monitoring, security operations, and authorized testing.



\---



\## Core Features



\### Document Honeytokens



\- Generates document-based honeytokens.

\- Supports Excel-based honeytoken documents.

\- Embeds unique honeytoken identifiers.

\- Creates trigger/callback URLs.

\- Tracks token activation and trigger history.

\- Supports confidential-document classifications.



\### Detection \& Risk Scoring



The detection engine evaluates activity using multiple indicators, including:



\- Confidential document access.

\- Honeytoken severity.

\- Source IP identification.

\- Repeated access to the same honeytoken.

\- Repeated activity from the same IP.



Events are assigned risk scores and severity levels based on the detection logic.



\### Security Alerts



The platform creates alerts from detected honeytoken activity and supports:



\- OPEN

\- ACKNOWLEDGED

\- RESOLVED



Authorized security analysts and administrators can manage alert status.



\### IP Intelligence



Public source IP addresses can be enriched with geographic and network intelligence.



Private/local addresses are identified appropriately instead of being treated as public Internet sources.



\### MITRE ATT\&CK Mapping



Detected activity can be mapped to relevant MITRE ATT\&CK techniques, including examples such as:



\- T1083 — File and Directory Discovery

\- T1005 — Data from Local System

\- T1071.001 — Web Protocols



\### Audit Trail



Administrative and security activity is recorded in an audit trail.



Audit records can contain:



\- Event IDs

\- Alert IDs

\- Honeytoken IDs

\- Risk scores

\- Severity

\- Detection reasons

\- Source IP intelligence

\- MITRE mappings

\- User-agent information

\- Status changes

\- Timestamps



\### SOC Dashboard



The web dashboard provides:



\- Security overview

\- Alert monitoring

\- Honeytoken management

\- Security event investigation

\- Analytics

\- Audit trail

\- Honeytoken details

\- Alert lifecycle management

\- Authentication and role display

\- Automatic data refresh



The existing dark SOC interface is intentionally kept focused on operational monitoring.



\---



\## Architecture



```text

&#x20;                   +----------------------+

&#x20;                   |   Honeytoken File    |

&#x20;                   |   Excel Document     |

&#x20;                   +----------+-----------+

&#x20;                              |

&#x20;                              | Trigger / Callback

&#x20;                              v

&#x20;                   +----------------------+

&#x20;                   |    FastAPI Backend   |

&#x20;                   +----------+-----------+

&#x20;                              |

&#x20;             +----------------+----------------+

&#x20;             |                |                |

&#x20;             v                v                v

&#x20;      +-------------+  +-------------+  +-------------+

&#x20;      | Detection   |  | IP Threat   |  |   MITRE     |

&#x20;      | \& Risk      |  | Intelligence|  | ATT\&CK Map  |

&#x20;      +------+------+  +------+------+  +------+------+

&#x20;             |                |                |

&#x20;             +----------------+----------------+

&#x20;                              |

&#x20;                              v

&#x20;                   +----------------------+

&#x20;                   | Security Event /     |

&#x20;                   | Alert / Audit Log    |

&#x20;                   +----------+-----------+

&#x20;                              |

&#x20;             +----------------+----------------+

&#x20;             |                                 |

&#x20;             v                                 v

&#x20;      +-------------+                   +-------------+

&#x20;      | SOC         |                   | Telegram    |

&#x20;      | Dashboard   |                   | Notification|

&#x20;      +-------------+                   +-------------+

```



\---



\## Technology Stack



\### Backend



\- Python

\- FastAPI

\- SQLAlchemy

\- SQLite

\- Pydantic

\- JWT authentication

\- bcrypt password hashing



\### Frontend



\- HTML5

\- CSS3

\- JavaScript

\- Bootstrap-based interface components



\### Security



\- JWT-based authentication

\- Role-based access control

\- Security headers

\- Restricted CORS

\- Trusted host validation

\- Audit logging

\- Risk scoring

\- MITRE ATT\&CK mapping

\- IP intelligence



\### Notifications



\- Telegram notifications

\- Email notification framework present but currently disabled



\---



\## Authentication \& RBAC



The API uses JWT-based authentication.



Three application roles are currently defined:



| Role | Access |

|---|---|

| ADMIN | Full administrative access |

| SOC\_ANALYST | Monitoring, investigation, and alert-management access |

| VIEWER | Read-only monitoring access |



\### Access Summary



| Capability | ADMIN | SOC\_ANALYST | VIEWER |

|---|:---:|:---:|:---:|

| View dashboard data | Yes | Yes | Yes |

| View honeytokens | Yes | Yes | Yes |

| Create honeytokens | Yes | No | No |

| Activate/deactivate honeytokens | Yes | No | No |

| View security events | Yes | Yes | Yes |

| View alerts | Yes | Yes | Yes |

| Acknowledge alerts | Yes | Yes | No |

| Resolve alerts | Yes | Yes | No |

| View analytics | Yes | Yes | Yes |

| View audit trail | Yes | Yes | Yes |



The public honeytoken trigger endpoint remains unauthenticated by design so that a document can generate a detection event when opened or triggered.



\---



\## API Security Hardening



The FastAPI application includes several security controls:



\- JWT authentication for protected endpoints.

\- Role-based authorization.

\- Restricted CORS origins.

\- Trusted host validation.

\- `X-Content-Type-Options: nosniff`

\- `X-Frame-Options: DENY`

\- `Referrer-Policy: no-referrer`

\- Restricted browser permissions policy.

\- `Cache-Control: no-store`

\- Bearer token authentication.

\- Password hashing using bcrypt.

\- Configurable JWT expiration.

\- Environment-based JWT secret configuration.



\---



\## API Endpoints



\### Authentication



```text

POST /api/auth/login

GET  /api/auth/me

```



\### Honeytokens



```text

GET  /api/tokens

GET  /api/tokens/{token\_id}

GET  /api/tokens/{token\_id}/document

POST /api/tokens

PUT  /api/tokens/{token\_id}/activate

PUT  /api/tokens/{token\_id}/deactivate

```



\### Security Events



```text

POST /api/events

GET  /api/events

GET  /api/events/id/{event\_id}

POST /api/events/trigger/{token\_id}

```



The trigger endpoint is intentionally public.



\### Alerts



```text

GET  /api/alerts

GET  /api/alerts/{alert\_id}

GET  /api/alerts/stats

PUT  /api/alerts/{alert\_id}/acknowledge

PUT  /api/alerts/{alert\_id}/resolve

```



\### Analytics



```text

GET /api/analytics/overview

GET /api/analytics/risk

GET /api/analytics/severity

GET /api/analytics/events

GET /api/analytics/tokens

GET /api/analytics/alerts

```



\### Audit



```text

GET /api/audit

GET /api/audit/{audit\_id}

```



\---



\## Project Structure



```text

active-honeytoken/

|

+---app/

|   +---api/

|   |   +---alerts.py

|   |   +---analytics.py

|   |   +---audit.py

|   |   +---auth.py

|   |   +---events.py

|   |   +---tokens.py

|   |

|   +---detection/

|   |   +---audit.py

|   |   +---correlation.py

|   |   +---mitre.py

|   |   +---siem.py

|   |   +---threat\_intel.py

|   |

|   +---honeytokens/

|   |   +---documents.py

|   |

|   +---notifications/

|   |   +---config.py

|   |   +---email.py

|   |   +---telegram.py

|   |   +---webhook.py

|   |

|   +---database.py

|   +---main.py

|   +---models.py

|   +---schemas.py

|   +---security.py

|

+---dashboard/

|   +---index.html

|   +---app.js

|   +---style.css

|

+---documents/

|

+---scripts/

|   +---generate\_document.py

|   +---get\_telegram\_chat\_id.py

|   +---webhook\_receiver.py

|

+---tests/

|   +---conftest.py

|   +---test\_api.py

|

+---Dockerfile

+---docker-compose.yml

+---requirements.txt

+---.env.example

+---.gitignore

+---openapi.txt

+---README.md

```



\---



\## Requirements



\- Python 3.10+

\- Windows, Linux, or another supported Python environment

\- Internet access for external IP intelligence services when public IP enrichment is required

\- A modern web browser



\---



\## Installation



Clone the repository:



```bash

git clone <YOUR-GITHUB-REPOSITORY-URL>

cd active-honeytoken

```



Create a virtual environment:



\### Windows PowerShell



```powershell

python -m venv venv

.\\venv\\Scripts\\Activate.ps1

```



\### Linux



```bash

python3 -m venv venv

source venv/bin/activate

```



Install dependencies:



```bash

pip install -r requirements.txt

```



\---



\## Environment Configuration



Create a `.env` file based on `.env.example`.



Example:



```env

JWT\_SECRET\_KEY=CHANGE\_THIS\_TO\_A\_LONG\_RANDOM\_SECRET

ACCESS\_TOKEN\_EXPIRE\_MINUTES=60

```



Do not commit `.env` files or real secrets to GitHub.



\---



\## Running the Backend



From the project root:



```bash

python -m uvicorn app.main:app --reload

```



The API will normally be available at:



```text

http://127.0.0.1:8000

```



FastAPI documentation is available through the standard documentation routes when enabled.



\---



\## Running the Dashboard



Open another terminal:



```bash

cd dashboard

python -m http.server 5500

```



Then open:



```text

http://127.0.0.1:5500

```



\---



\## Demo Accounts



The development environment includes role-based demonstration accounts.



| Username | Role |

|---|---|

| admin | ADMIN |

| analyst | SOC\_ANALYST |

| viewer | VIEWER |



Demo passwords should be changed or replaced before any production deployment.



\---



\## Example Detection Workflow



A typical test workflow is:



```text

1\. Create a honeytoken.

&#x20;       |

&#x20;       v

2\. Generate the document.

&#x20;       |

&#x20;       v

3\. Open/trigger the honeytoken.

&#x20;       |

&#x20;       v

4\. Backend receives the callback.

&#x20;       |

&#x20;       v

5\. Security event is created.

&#x20;       |

&#x20;       v

6\. Detection engine calculates risk.

&#x20;       |

&#x20;       v

7\. IP intelligence is collected.

&#x20;       |

&#x20;       v

8\. MITRE techniques are mapped.

&#x20;       |

&#x20;       v

9\. Security alert is generated.

&#x20;       |

&#x20;       v

10\. Audit record is created.

&#x20;       |

&#x20;       v

11\. SOC dashboard displays the activity.

```



Repeated access to the same honeytoken or repeated activity from the same source can increase the resulting risk assessment.



\---



\## Testing



The project includes automated API tests covering authentication, authorization, honeytokens, events, alerts, analytics, and audit functionality.



Current verified test result:



```text

24 passed, 1 warning

```



The warning is related to a Starlette/httpx test-client deprecation notice and does not currently cause test failure.



Run the tests with:



```bash

pytest -q

```



\---



\## Security Testing



The project has been tested for:



\- Authentication enforcement.

\- JWT authorization.

\- Role-based access control.

\- Viewer read-only restrictions.

\- Analyst permissions.

\- Administrative permissions.

\- Alert acknowledgement.

\- Alert resolution.

\- Honeytoken activation/deactivation restrictions.

\- Protected API access.

\- CORS restrictions.

\- Trusted host validation.

\- Security response headers.

\- Honeytoken triggering.

\- Risk scoring.

\- IP intelligence.

\- MITRE ATT\&CK mapping.

\- Audit logging.



\---



\## Docker



The project includes Docker configuration for containerized deployment.



Build and start:



```bash

docker compose up --build

```



The current development configuration uses SQLite.



\---



\## Current Limitations



This project is primarily designed as a defensive research and portfolio system.



Current limitations include:



\- SQLite is used for the current deployment.

\- Application users are currently defined in application configuration rather than a dedicated production identity provider.

\- Email notifications are currently disabled.

\- The honeytoken callback endpoint is intentionally public.

\- Local development uses HTTP rather than production TLS.

\- External IP intelligence depends on the availability of the configured service.

\- Production deployment would require additional secrets management and infrastructure hardening.



\---



\## Recommended Production Improvements



For a production deployment, consider:



\- PostgreSQL or another production database.

\- Enterprise identity provider integration.

\- Multi-factor authentication.

\- HTTPS/TLS.

\- Secure secrets management.

\- Centralized SIEM integration.

\- Redis or another event/queue system.

\- Rate limiting.

\- Reverse proxy/WAF.

\- Container orchestration.

\- Structured security monitoring.

\- Centralized logging.

\- Backup and disaster recovery.

\- Automated CI/CD security scanning.

\- More extensive threat-intelligence integrations.



\---



\## Security Philosophy



Honeytokens work because legitimate users normally have no reason to interact with them.



A triggered honeytoken can therefore provide a high-value signal for investigation, particularly when combined with:



\- Source information

\- Repeated activity

\- Risk scoring

\- Threat intelligence

\- MITRE ATT\&CK context

\- Alert correlation

\- Audit records



The goal of this project is not simply to detect an event, but to provide security personnel with enough context to investigate the event efficiently.



\---



\## Portfolio Value



This project demonstrates practical experience with:



\- Defensive cybersecurity engineering

\- Security monitoring

\- Honeytoken deployment

\- Detection engineering

\- Risk scoring

\- REST API development

\- FastAPI

\- JWT authentication

\- RBAC

\- Security hardening

\- Threat intelligence

\- MITRE ATT\&CK

\- Audit logging

\- SOC dashboard development

\- Telegram security notifications

\- Automated testing

\- Docker

\- Git/GitHub workflows



\---



\## Project Status



The core system is functional and has been tested end-to-end.



Verified capabilities include:



\- Honeytoken generation

\- Honeytoken triggering

\- Security event creation

\- Risk scoring

\- Alert generation

\- Alert acknowledgement

\- Alert resolution

\- IP intelligence

\- MITRE ATT\&CK mapping

\- Audit trail

\- JWT authentication

\- Role-based access control

\- SOC dashboard monitoring

\- Telegram notification support

\- Automated API testing



\---



\## Author



\*\*JOBBEN\*\*  

Cybersecurity Researcher \& Developer  

BSc Cyber Security



This project was developed as a defensive cybersecurity portfolio project focused on 

honeytoken-based breach detection, security monitoring, alerting, and SOC operations.



\---



\## Disclaimer



This project is intended for defensive cybersecurity research, education, security monitoring, and authorized security testing only.



Do not deploy honeytokens or monitoring mechanisms against systems, users, networks, or organizations without appropriate authorization.



