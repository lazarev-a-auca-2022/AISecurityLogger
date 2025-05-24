#!/bin/bash

# Script to rebuild and restart the AI Security Logger container

echo "Stopping and removing containers..."
docker-compose down

echo "Rebuilding the containers..."
docker-compose build

echo "Starting the containers..."
docker-compose up -d

echo "Showing logs..."
docker-compose logs -f
