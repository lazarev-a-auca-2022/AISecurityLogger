from fastapi import FastAPI
from unsloth import FastLanguageModel
import torch

app = FastAPI()

# Placeholder for fine-tuned model and tokenizer
model = None
tokenizer = None

@app.on_event("startup")
async def startup_event():
    """
    Load the fine-tuned model and tokenizer on startup.
    """
    global model, tokenizer
    # Load the fine-tuned model and tokenizer if they exist
    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name = "fine_tuned_model", # Load from the saved directory
            max_seq_length = 2048, # Or your custom maximum sequence length
            dtype = None, # None for auto detection. Float16 for Tesla T4, V100, Bfloat16 for Ampere+
            load_in_4bit = True, # Use 4bit quantization
        )
        print("Fine-tuned model and tokenizer loaded successfully.")
    except Exception as e:
        print(f"Could not load fine-tuned model: {e}")
        print("Using placeholder model and tokenizer.")
        # TODO: Potentially load a base model or handle this case appropriately
        model = None # Ensure model is None if loading fails
        tokenizer = None # Ensure tokenizer is None if loading fails

@app.post("/analyze_log")
async def analyze_log(log_data: dict):
    """
    Analyze incoming log data using the fine-tuned NLP model.
    """
    if model is None or tokenizer is None:
        print("Model or tokenizer not loaded. Cannot perform analysis.")
        return {"analysis": "error", "message": "Model not loaded."}

    # Format the log data for the model
    # This is a basic example, you might need more sophisticated formatting
    instruction = "Analyze the following log entry for suspicious activity."
    input_text = str(log_data) # Convert log data to string
    prompt = f"""Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Instruction:
{instruction}

### Input:
{input_text}

### Response:
"""

    # Tokenize the input
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    # Generate analysis result
    outputs = model.generate(**inputs, max_new_tokens=64, use_cache=True) # Generate a short response

    # Decode the output
    analysis_result_text = tokenizer.batch_decode(outputs, skip_special_tokens=True)[0]

    # Extract only the response part
    response_tag = "### Response:\n"
    response_start = analysis_result_text.find(response_tag)
    if response_start != -1:
        analysis_result_text = analysis_result_text[response_start + len(response_tag):].strip()
    else:
        analysis_result_text = "Analysis could not be extracted."


    print(f"Received log data for analysis: {log_data}")
    print(f"Analysis result: {analysis_result_text}")

    analysis_result = {"analysis": analysis_result_text, "log": log_data}
    return analysis_result

def fine_tune_model():
    """
    Fine-tune the NLP model using unsloth.
    """
    max_seq_length = 2048 # Or your custom maximum sequence length
    dtype = None # None for auto detection. Float16 for Tesla T4, V100, Bfloat16 for Ampere+
    load_in_4bit = True # Use 4bit quantization to reduce memory usage

    # Load model and tokenizer
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name = "unsloth/llama-3-8b-Instruct-bnb-4bit", # Or any other model you want to fine-tune
        max_seq_length = max_seq_length,
        dtype = dtype,
        load_in_4bit = load_in_4bit,
    )

    # Add LoRA adapters
    model = FastLanguageModel.get_peft_model(
        model,
        r = 16, # Choose any number from 8 to 64
        target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                          "gate_proj", "up_proj", "down_proj", "linear"],
        lora_alpha = 16,
        lora_dropout = 0, # Supports Dropout, but not recommended
        bias = "none",    # Supports bias, but not recommended
        use_gradient_checkpointing = "unsloth", # True or "unsloth" for optimized gradient checkpointing
        random_state = 3407,
        use_rslora = False,  # We support RS LoRA
        loftq_config = None, # And LoftQ
    )

    # Prepare dummy data for demonstration
    # In a real scenario, you would load and format your security log data here
    alpaca_prompt = """Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Instruction:
{}

### Input:
{}

### Response:
{}"""

    # Dummy security log data
    dummy_data = [
        {"instruction": "Analyze the following log entry for suspicious activity.", "input": "Login failed for user 'admin' from IP '192.168.1.10'.", "response": "Potential brute-force attempt detected from IP 192.168.1.10."},
        {"instruction": "Identify the type of security event in this log.", "input": "Firewall blocked connection from 203.0.113.5 on port 22.", "response": "Blocked port scan from IP 203.0.113.5."},
    ]

    # Format data for training
    formatted_data = [alpaca_prompt.format(item["instruction"], item["input"], item["response"]) for item in dummy_data]

    # Create a dummy dataset (replace with your actual dataset loading)
    from datasets import Dataset
    dataset = Dataset.from_dict({"text": formatted_data})

    # Train the model
    trainer = model.get_trainer(
        train_dataset = dataset,
        max_seq_length = max_seq_length,
        args = model.get_training_arguments(
            per_device_train_batch_size = 2,
            gradient_accumulation_steps = 4,
            warmup_steps = 5,
            max_steps = 60, # Reduced steps for a quick example
            learning_rate = 2e-4,
            fp16 = not torch.cuda.is_bf16_supported(),
            bf16 = torch.cuda.is_bf16_supported(),
            logging_steps = 1,
            optim = "adamw_8bit",
            weight_decay = 0.01,
            lr_scheduler_type = "linear",
            seed = 3407,
            output_dir = "outputs", # Directory to save the model
        ),
    )

    trainer.train()

    # Save the fine-tuned model and tokenizer
    model.save_pretrained("fine_tuned_model") # Save the model
    tokenizer.save_pretrained("fine_tuned_model") # Save the tokenizer

    print("Fine-tuning complete. Model saved to 'fine_tuned_model' directory.")


if __name__ == "__main__":
    import uvicorn
    # For demonstration, you could call fine_tune_model() here
    # fine_tune_model()
    uvicorn.run(app, host="0.0.0.0", port=8000)
