# Security Monitoring Lab

A local security monitoring project built around a fictional document-sharing app. It
turns login and document-access activity into security events, runs detection rules,
and lets an analyst investigate alerts with their underlying evidence.

## What it does

- Provides a document app with user roles and organization-based access controls.
- Records application activity and ingests events into PostgreSQL.
- Detects failed logins followed by a success and repeated denied document access.
- Shows alerts, supporting events, and case decisions in a React interface.

The backend uses Python and FastAPI. The frontend uses React and TypeScript.
PostgreSQL runs locally through Docker Compose. This is a portfolio lab, not a
production SIEM.

## Run locally

Requires Python 3.10+, Node.js 24.15+, and Docker.

1. Install dependencies and create your local configuration:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -e '.[dev]'
   cd frontend && npm ci && cd ..
   cp .env.example .env
   ```

2. In `.env`, set `POSTGRES_PASSWORD` and use the same password in `DATABASE_URL`
   and `TEST_DATABASE_URL`. Set `COLLECTOR_TOKEN` to a random value of at least
   16 characters and `SEED_USER_PASSWORD` to a password of at least 12 characters.

3. Start PostgreSQL and prepare the database:

   ```bash
   docker compose up -d --wait
   python -m scripts.migrate
   python -m scripts.seed
   ```

4. Start the API and frontend in separate terminals:

   ```bash
   uvicorn backend.api:create_app --factory --no-access-log
   ```

   ```bash
   cd frontend && npm run dev
   ```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Sign in as
`analyst@lab.example.test` with `SEED_USER_PASSWORD` to view alerts. To generate
sample alerts, run these commands while the API is running:

```bash
python -m scripts.generate_scenarios suspicious
python -m scripts.run_detection
```

## Documentation

- [Demo walkthrough](docs/DEMO.md)
- [Technical specification](docs/TECHNICAL.md)
- [Codebase walkthrough](docs/CODEBASE_WALKTHROUGH.md)
- [Splunk exercise](splunk/README.md)
