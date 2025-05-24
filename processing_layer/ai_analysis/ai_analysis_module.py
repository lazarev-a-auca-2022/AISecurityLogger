from fastapi import FastAPI
import google.generativeai as genai
import os

app = FastAPI()

# Global variable for the generative model
gemini_model = None

@app.on_event("startup")
async def startup_event():
    """
    Configure Google AI Studio and load the generative model on startup.
    """
    global gemini_model
    google_api_key = os.getenv("GOOGLE_API_KEY")
    if not google_api_key:
        print("GOOGLE_API_KEY environment variable not set. AI analysis will not function.")
        return

    try:
        genai.configure(api_key=google_api_key)
        gemini_model = genai.GenerativeModel('gemini-pro') # Or 'gemini-1.5-pro-latest' or other suitable model
        print("Google AI Studio model loaded successfully.")
    except Exception as e:
        print(f"Could not configure Google AI Studio or load model: {e}")
        gemini_model = None

@app.post("/analyze_log")
async def analyze_log(log_data: dict):
    """
    Analyze incoming log data using the Google AI Studio model.
    """
    if gemini_model is None:
        print("Google AI Studio model not loaded. Cannot perform analysis.")
        return {"analysis": "error", "message": "AI model not loaded or configured."}

    input_text = f"Analyze the following security log for potential threats, anomalies, or important events. Provide a concise summary and categorize the event (e.g., 'Informational', 'Warning', 'Critical', 'Suspicious Activity', 'Attack Attempt'):\n\n{log_data}"

    try:
        response = gemini_model.generate_content(input_text)
        analysis_result_text = response.text
    except Exception as e:
        print(f"Error during AI analysis: {e}")
        return {"analysis": "error", "message": f"AI analysis failed: {e}"}

    print(f"Received log data for analysis: {log_data}")
    print(f"AI Analysis result: {analysis_result_text}")

    analysis_result = {"analysis": analysis_result_text, "log": log_data}
    return analysis_result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
