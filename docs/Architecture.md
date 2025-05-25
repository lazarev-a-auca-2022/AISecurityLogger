      
# AI-Powered Log Processor - Architecture (MVP)

## 1. Overview

This document outlines the architecture for an MVP (Minimum Viable Product) of an AI-Powered Log Processor. The system is designed to run on a server managed by FastPanel, ingesting various server and application logs. It utilizes an external NLP model via OpenRouter API for threat detection and generates concise threat/error summaries. The architecture prioritizes simplicity for MVP, with considerations for future scalability.

## Disclaimer
The program must be developed and tested in a Docker container. 

## 2. Core Goals (MVP)

*   Ingest logs from configurable sources (e.g., syslog, web server logs, application logs).
*   Pre-process and normalize log entries.
*   Send relevant log snippets/patterns to an OpenRouter NLP model for analysis.
*   Receive and interpret the NLP model's threat assessment.
*   Store detected threats and their summaries.
*   Provide a simple mechanism to view these summaries (e.g., a daily digest file or a simple DB query).
*   Ensure secure handling of the OpenRouter API key.
*   Be deployable and manageable within a FastPanel environment.

## 3. Architecture Diagram (Conceptual)

    
+---------------------+ +---------------------+ +-----------------------+
| Log Sources |----->| Log Ingestor & |----->| AI Threat Analyzer |
| (e.g., syslog, | | Preprocessor | | (Python Service) |
| Nginx, App Logs) | | (Python Script/ | | - Formats request |
+---------------------+ | Service) | | - Calls OpenRouter API|
| - Watches files/dirs| | - Parses response |
| - Basic parsing | +-----------+-----------+
| - Filtering | |
+---------+-----------+ | (Threat Summary)
| |
|(Filtered/Normalized Logs) |
| |
v v
+---------------------+ +-----------------------+
| Log & Threat Storage|----->| Summary Access Point |
| (SQLite DB / | | (e.g., Cron-generated |
| JSON Log Files) | | Report, Simple CLI) |
+---------------------+ +-----------------------+

+-----------------------------+
| Configuration |
| (config.ini / .env file) |
| - Log paths |
| - OpenRouter API Key |
| - NLP Model ID |
| - Detection Thresholds |
+-----------------------------+

## 4. Components

### 4.1. Log Sources
*   **Description:** Standard system and application logs.
    *   System Logs (e.g., `/var/log/syslog`, `/var/log/auth.log`)
    *   Web Server Logs (e.g., Nginx `access.log`, `error.log` managed by FastPanel)
    *   Application Logs (custom application log files)
*   **Integration:** The processor will need read access to these files/streams.

### 4.2. Configuration
*   **Description:** A central place for all settings.
*   **Technology:** `.env` file (using `python-dotenv`) or `config.ini` (using `configparser`).
*   **Contents (MVP):**
    *   `OPENROUTER_API_KEY`
    *   `OPENROUTER_MODEL_ID` (e.g., "openai/gpt-3.5-turbo-instruct" or a free tier model)
    *   `LOG_SOURCES`: A list of files or directories to monitor.
    *   `PROCESSING_INTERVAL`: How often to check for new logs.
    *   `SENSITIVITY_KEYWORDS`: Simple keywords to pre-filter logs before sending to AI (e.g., "error", "failed", "denied", "warning", "critical").
    *   `DB_PATH` (if using SQLite) or `OUTPUT_LOG_DIR`.

### 4.3. Log Ingestor & Preprocessor
*   **Description:** A service or script responsible for collecting, tailing, and performing initial processing of log entries.
*   **Technology:** Python script/service (e.g., using libraries like `watchdog` for file monitoring or simply `tail -f` piped to script).
*   **Responsibilities:**
    1.  Monitor configured log files/directories for new entries.
    2.  Perform basic parsing (e.g., timestamp extraction, regex for common formats if possible).
    3.  Filter logs based on `SENSITIVITY_KEYWORDS` or basic heuristics to reduce noise and API calls.
    4.  Queue or directly pass relevant log entries to the AI Threat Analyzer.
*   **Scalability Note:** For MVP, this can be a single Python script. For scaling, this could involve a dedicated log shipper (like Filebeat) sending to a message queue (like Redis or RabbitMQ) which the preprocessor consumes.

### 4.4. AI Threat Analyzer
*   **Description:** The core component that interacts with the OpenRouter NLP model.
*   **Technology:** Python service/module (using `requests` library for API calls).
*   **Responsibilities:**
    1.  Receive pre-processed log entries.
    2.  Construct a suitable prompt for the OpenRouter NLP model. The prompt should instruct the model to:
        *   Analyze the provided log snippet(s) for potential security threats, errors, or anomalies.
        *   Provide a concise summary of the findings.
        *   Categorize the severity (e.g., INFO, WARNING, ERROR, CRITICAL).
        *   Example Prompt: `"Analyze the following log entries for security threats or critical errors. Summarize any findings concisely and indicate severity (INFO, WARNING, ERROR, CRITICAL):\n\n[LOG_ENTRY_1]\n[LOG_ENTRY_2]..."`
    3.  Make an API call to OpenRouter using the configured API key and model.
    4.  Parse the JSON response from OpenRouter.
    5.  Extract the threat summary and severity.
    6.  Pass the enriched information (original log, AI summary, severity) to Log & Threat Storage.
*   **Security:** The OpenRouter API key must be read from the secure configuration and not hardcoded.

### 4.5. Log & Threat Storage
*   **Description:** Stores both the original (or pre-processed) logs that triggered an alert and the AI-generated threat summaries.
*   **Technology (MVP):**
    *   **SQLite Database:** Simple, file-based, easy to set up. Schema: `(timestamp, source_log, original_log_entry, ai_summary, severity, processed_at)`.
    *   **Alternatively (simpler MVP):** Structured JSON log files appended to a daily/hourly file.
*   **Scalability Note:** For future scaling, this would migrate to a more robust database like PostgreSQL or a specialized log database.

### 4.6. Summary Access Point
*   **Description:** A way for the user/admin to view the detected threats and summaries.
*   **Technology (MVP):**
    *   **Cron Job + Script:** A Python script run by cron (e.g., daily) that queries the SQLite DB (or parses JSON logs) and generates a simple text report (e.g., emailed or saved to a file in a FastPanel-accessible web directory).
    *   **Simple CLI Tool:** A command-line interface to query recent threats.
*   **FastPanel Integration:** The output report could be placed in a directory served by Nginx/Apache, making it viewable via a browser.

## 5. Data Flow

1.  **Log Generation:** System services, web servers, and applications generate logs.
2.  **Ingestion & Pre-processing:** The `Log Ingestor & Preprocessor` tails/reads these logs. It applies basic filters (keywords, regex) and normalization.
3.  **AI Analysis Trigger:** If a log entry passes pre-processing filters, it's sent to the `AI Threat Analyzer`.
4.  **OpenRouter API Call:** The `AI Threat Analyzer` formats a prompt with the log data and sends it to the configured OpenRouter NLP model.
5.  **AI Response:** OpenRouter processes the request and returns a JSON response containing the analysis (threat summary, severity).
6.  **Storage:** The `AI Threat Analyzer` parses this response and stores the original log snippet, AI summary, and severity in the `Log & Threat Storage` (SQLite DB or JSON files).
7.  **Reporting:** The `Summary Access Point` (e.g., daily cron job) queries the storage and generates a human-readable summary/report.

## 6. FastPanel Integration

*   **Deployment:** The Python application (Ingestor, Analyzer) will run as a systemd service or a supervised script. FastPanel's interface might not directly manage Python apps, but server access (SSH, file manager) allows setup.
*   **Log Access:** FastPanel configures web servers (Nginx/Apache), so their log paths are known and can be configured in the processor.
*   **Configuration Management:** Config files (`.env` or `config.ini`) can be managed via FastPanel's file editor or SSH.
*   **Resource Monitoring:** FastPanel's server monitoring can help observe the resource usage of the processor.
*   **Report Access (Optional):** If reports are generated as HTML/text files, they can be placed in a web-accessible directory configured via FastPanel.
*   **Firewall:** Ensure outbound connections to `openrouter.ai` are allowed if a firewall is active.

## 7. Scalability Considerations (Beyond MVP)

*   **Message Queue:** Introduce a message queue (e.g., Redis, RabbitMQ) between the `Log Ingestor` and `AI Threat Analyzer` to decouple components and handle bursts of logs.
*   **Dedicated Workers:** Scale the `AI Threat Analyzer` component by running multiple instances (workers) consuming from the message queue.
*   **Database:** Migrate from SQLite to a more robust database like PostgreSQL for better concurrency and data management.
*   **Advanced Pre-processing:** Implement more sophisticated pre-filtering and log parsing before sending to the AI to reduce costs and improve AI focus.
*   **Rate Limiting & Retries:** Implement robust rate limiting and retry mechanisms for OpenRouter API calls.
*   **Web UI:** Develop a simple web interface (e.g., using Flask/FastAPI) for configuration, viewing dashboards, and managing threats, potentially hosted via FastPanel.

## 8. Technology Stack (MVP Summary)

*   **Language:** Python 3.x
*   **Key Python Libraries:**
    *   `requests` (for OpenRouter API)
    *   `python-dotenv` or `configparser` (for configuration)
    *   `sqlite3` (for database)
    *   `watchdog` (optional, for efficient file monitoring)
    *   Standard library modules (`os`, `re`, `json`, `datetime`)
*   **External Services:** OpenRouter API
*   **Storage:** SQLite / Flat Files (JSON)
*   **Deployment Environment:** Linux server managed by FastPanel.
*   **Process Management:** `systemd` service or a simple supervisor script.
