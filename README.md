# AI-Powered Security Log Processor

An AI-powered log analysis system that monitors server logs for potential security threats and generates summaries using OpenRouter's API.

## Features

- Ingests logs from various sources (syslog, web server logs, application logs)
- Pre-processes and normalizes log entries
- Uses OpenRouter's AI models to analyze logs for security threats
- Stores detected threats and their summaries in a SQLite database
- Generates HTML and JSON reports of detected threats
- Runs in Docker for easy deployment and management

## Architecture

The system consists of the following components:

1. **Log Ingestor**: Monitors configured log files/directories for new entries
2. **Threat Analyzer**: Sends logs to OpenRouter's AI model and processes responses
3. **Database**: Stores detected threats and their summaries
4. **Report Generator**: Creates periodic reports of detected threats

## Quick Start

### Prerequisites

- Docker and Docker Compose
- OpenRouter API key (get one from [OpenRouter](https://openrouter.ai))

### Setup

1. Clone this repository:

```bash
git clone https://github.com/yourusername/AISecurityLogger.git
cd AISecurityLogger
```

2. Run the setup script to create the .env file:

```bash
./run.sh setup
```

3. Edit the .env file to add your OpenRouter API key and configure log sources:

```bash
nano .env
```

4. Start the application:

```bash
./run.sh start
```

### Usage

- View logs: `./run.sh logs`
- Check status: `./run.sh status`
- Access reports: Open http://localhost:8359 in your browser
- Stop the application: `./run.sh stop`
- Rebuild containers: `./run.sh rebuild`

## Configuration

Configuration is done through the `.env` file. The following options are available:

- `OPENROUTER_API_KEY`: Your OpenRouter API key
- `OPENROUTER_MODEL_ID`: The model to use (default: "openai/gpt-3.5-turbo")
- `LOG_SOURCES`: Comma-separated list of files or directories to monitor
- `PROCESSING_INTERVAL`: How often to check for new logs (in seconds)
- `SENSITIVITY_KEYWORDS`: Keywords to pre-filter logs
- `DB_PATH`: Path to the SQLite database
- `OUTPUT_LOG_DIR`: Directory for reports
- `REPORT_SCHEDULE`: How often to generate reports (hourly, daily, weekly)

## Testing

You can generate test logs to verify the system works:

```bash
./tools/generate_test_logs.py --num-logs 20 --interval 0.5
```

The logs will be written to `data/logs/sample.log` by default.

## Docker Compose Services

The application runs with three containers:

1. **ai-security-logger**: The main application
2. **redis**: For message queueing
3. **nginx**: A simple web server to view reports


## License

MIT License

## Acknowledgments

- This project uses the OpenRouter API for AI analysis
- Built for use with FastPanel server management
