# Use an official Python runtime as a parent image
FROM python:3.12-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY ai_analysis_module.py .

# Expose the port that FastAPI will run on
EXPOSE 8000

# Command to run the FastAPI application
CMD ["uvicorn", "ai_analysis_module:app", "--host", "0.0.0.0", "--port", "8000"]
