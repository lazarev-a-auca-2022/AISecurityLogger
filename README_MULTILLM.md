# AI Security Logger - Multi-LLM Provider Support

This document explains how to configure AI Security Logger to work with different Language Model (LLM) providers for log analysis.

## Supported LLM Providers

AI Security Logger now supports the following LLM providers:

1. **OpenRouter** (default) - A single API that gives access to multiple models from various providers
2. **OpenAI** - Direct access to GPT models like GPT-4o, GPT-4, and GPT-3.5 Turbo
3. **Google AI** - Access to Gemini models
4. **Azure OpenAI** - Microsoft's managed OpenAI service
5. **Anthropic** - Access to Claude models
6. **Custom** - Support for other LLM providers with a compatible API

## Configuration

To configure your preferred LLM provider, you need to set the appropriate environment variables. You can do this in a `.env` file or directly in the `docker-compose.yml` file.

### Basic Configuration

The most important setting is the `AI_PROVIDER` variable, which determines which provider to use:

```
AI_PROVIDER=openrouter  # Change to: openai, google, azure, anthropic, or custom
```

### Provider-Specific Configuration

#### OpenRouter (Default)

```
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL_ID=openai/gpt-3.5-turbo  # Format: provider/model-name
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

#### OpenAI

```
AI_PROVIDER=openai
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL_ID=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_ORGANIZATION_ID=your_org_id_if_applicable  # Optional
```

#### Google AI (Gemini)

```
AI_PROVIDER=google
GOOGLE_API_KEY=your_api_key_here
GOOGLE_MODEL_ID=gemini-1.5-pro
GOOGLE_BASE_URL=https://generativelanguage.googleapis.com
GOOGLE_API_VERSION=v1
```

#### Azure OpenAI

```
AI_PROVIDER=azure
AZURE_API_KEY=your_api_key_here
AZURE_MODEL_ID=gpt-4o-mini
AZURE_BASE_URL=https://your-resource-name.openai.azure.com
AZURE_API_VERSION=2023-05-15
AZURE_DEPLOYMENT_NAME=your-deployment-name
```

#### Anthropic (Claude)

```
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_api_key_here
ANTHROPIC_MODEL_ID=claude-3-haiku
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_API_VERSION=v1
```

#### Custom Provider

For a custom LLM provider with a compatible API:

```
AI_PROVIDER=custom
CUSTOM_API_KEY=your_api_key_here
CUSTOM_MODEL_ID=your_model_id
CUSTOM_BASE_URL=https://your-custom-api-url.com
CUSTOM_API_VERSION=v1  # Optional
```

You can also add custom parameters with the `CUSTOM_PARAM_` prefix:

```
CUSTOM_PARAM_temperature=0.7
CUSTOM_PARAM_header_X-Custom-Header=custom-value  # For custom headers
```

## Switching Providers

To switch providers, update your `.env` file or environment variables with the new provider settings, then restart the service:

```bash
docker-compose down
docker-compose up -d
```

## Troubleshooting

If you encounter issues with the AI provider:

1. Check your API key is correctly set
2. Verify the model ID is valid for the chosen provider
3. Check the API base URL is correct
4. Look for error messages in the logs with: `docker-compose logs ai-security-logger`
5. If you see "Failed to parse AI response as JSON" errors, the AI model may not be providing proper JSON responses - try a different model or provider

## Model Selection Guidance

For optimal security threat analysis performance:

- **OpenAI**: GPT-4 or GPT-4o provide the best analysis, while GPT-3.5 Turbo is more economical
- **Google**: Gemini 1.5 Pro offers good performance
- **Anthropic**: Claude 3 Opus or Claude 3 Sonnet provide excellent detailed analysis
- **OpenRouter**: Provides access to many models - "openai/gpt-4" and "anthropic/claude-3-opus" work well

Choose models based on your balance of performance needs and cost considerations.
