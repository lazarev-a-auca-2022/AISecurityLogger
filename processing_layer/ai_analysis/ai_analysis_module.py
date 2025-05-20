from fastapi import FastAPI
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

app = FastAPI()

# Placeholder for pre-trained model and tokenizer
model = None
tokenizer = None
device = "cpu" # Explicitly set device to CPU

@app.on_event("startup")
async def startup_event():
    """
    Load the pre-trained model and tokenizer on startup.
    """
    global model, tokenizer
    model_name = "distilbert-base-uncased-finetuned-sst-2-english" # Example CPU-compatible model
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        model.to(device) # Move model to CPU
        print(f"Model '{model_name}' and tokenizer loaded successfully on CPU.")
    except Exception as e:
        print(f"Could not load model '{model_name}': {e}")
        print("Using placeholder model and tokenizer.")
        model = None # Ensure model is None if loading fails
        tokenizer = None # Ensure tokenizer is None if loading fails

@app.post("/analyze_log")
async def analyze_log(log_data: dict):
    """
    Analyze incoming log data using the pre-trained NLP model.
    """
    if model is None or tokenizer is None:
        print("Model or tokenizer not loaded. Cannot perform analysis.")
        return {"analysis": "error", "message": "Model not loaded."}

    # Convert log data to string for analysis
    input_text = str(log_data)

    # Tokenize the input
    inputs = tokenizer(input_text, return_tensors="pt", truncation=True, padding=True).to(device) # Move inputs to CPU

    # Perform inference
    with torch.no_grad():
        outputs = model(**inputs)

    # Get the predicted class (for sentiment analysis example)
    # You would need to adapt this part based on the actual model used for log analysis
    predictions = torch.argmax(outputs.logits, dim=-1)
    analysis_result_text = "Positive" if predictions.item() == 1 else "Negative" # Example interpretation

    print(f"Received log data for analysis: {log_data}")
    print(f"Analysis result: {analysis_result_text}")

    analysis_result = {"analysis": analysis_result_text, "log": log_data}
    return analysis_result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
