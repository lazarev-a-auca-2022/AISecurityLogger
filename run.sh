#!/bin/bash
# This script helps run the AI Security Logger application

# Function to show help
show_help() {
    echo "AI Security Logger Control Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start       - Start the containers"
    echo "  stop        - Stop the containers"
    echo "  restart     - Restart the containers"
    echo "  logs        - View logs"
    echo "  status      - Check container status"
    echo "  rebuild     - Rebuild and restart containers"
    echo "  setup       - Initial setup (copy .env.example to .env)"
    echo "  shell       - Open a shell in the main container"
    echo "  reports     - Open reports directory"
    echo "  help        - Show this help message"
    echo ""
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        if ! docker compose version &> /dev/null; then
            echo "Error: Neither docker-compose nor docker compose is available"
            exit 1
        fi
        # Use docker compose subcommand
        DOCKER_COMPOSE="docker compose"
    else
        # Use docker-compose command
        DOCKER_COMPOSE="docker-compose"
    fi
}

# Run the setup
setup() {
    if [ ! -f .env ]; then
        echo "Creating .env file from .env.example..."
        cp .env.example .env
        echo "Please edit .env file and set your OpenRouter API key before starting the application."
        echo "You can use 'nano .env' or any text editor to make changes."
    else
        echo ".env file already exists."
    fi
}

# Run command based on user input
case "$1" in
    start)
        check_docker
        echo "Starting AI Security Logger containers..."
        $DOCKER_COMPOSE up -d
        echo "Containers started. View logs with: $0 logs"
        ;;
    stop)
        check_docker
        echo "Stopping AI Security Logger containers..."
        $DOCKER_COMPOSE down
        ;;
    restart)
        check_docker
        echo "Restarting AI Security Logger containers..."
        $DOCKER_COMPOSE restart
        ;;
    logs)
        check_docker
        echo "Showing logs (Ctrl+C to exit)..."
        $DOCKER_COMPOSE logs -f
        ;;
    status)
        check_docker
        echo "Container status:"
        $DOCKER_COMPOSE ps
        ;;
    rebuild)
        check_docker
        echo "Rebuilding and restarting containers..."
        $DOCKER_COMPOSE down
        $DOCKER_COMPOSE build --no-cache
        $DOCKER_COMPOSE up -d
        echo "Rebuild complete."
        ;;
    setup)
        setup
        ;;
    shell)
        check_docker
        echo "Opening shell in the main container..."
        $DOCKER_COMPOSE exec ai-security-logger bash
        ;;
    reports)
        if [ -d "reports" ]; then
            echo "Opening reports directory..."
            if command -v xdg-open &> /dev/null; then
                xdg-open reports/
            elif command -v open &> /dev/null; then
                open reports/
            else
                echo "Could not automatically open the directory."
                echo "Reports are located at: $(pwd)/reports"
            fi
        else
            echo "Reports directory not found."
        fi
        ;;
    help|*)
        show_help
        ;;
esac
