'use strict';

require('./env_loader');

const PROVIDERS = {
  openai: {
    envKey: 'OPENAI_API_KEY',
    defaultModel: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
    endpoint: 'https://api.openai.com/v1/responses',
    formatRequest(prompt, model) {
      return {
        body: JSON.stringify({
          model,
          input: [
            { role: 'system', content: [{ type: 'input_text', text: 'Return valid JSON only.' }] },
            { role: 'user', content: [{ type: 'input_text', text: prompt }] }
          ]
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    },
    extractText(data) {
      if (typeof data.output_text === 'string' && data.output_text.trim() !== '') {
        return data.output_text.trim();
      }
      if (!Array.isArray(data.output)) return '';
      const chunks = [];
      for (const item of data.output) {
        if (!Array.isArray(item.content)) continue;
        for (const content of item.content) {
          if (typeof content.text === 'string') chunks.push(content.text);
        }
      }
      return chunks.join('\n').trim();
    },
    authHeader(apiKey) {
      return { Authorization: `Bearer ${apiKey}` };
    }
  },

  anthropic: {
    envKey: 'ANTHROPIC_API_KEY',
    defaultModel: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
    endpoint: 'https://api.anthropic.com/v1/messages',
    formatRequest(prompt, model) {
      return {
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          system: 'Return valid JSON only.',
          messages: [{ role: 'user', content: prompt }]
        }),
        headers: { 'Content-Type': 'application/json', 'anthropic-version': '2023-06-01' }
      };
    },
    extractText(data) {
      if (!Array.isArray(data.content)) return '';
      return data.content
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('\n')
        .trim();
    },
    authHeader(apiKey) {
      return { 'x-api-key': apiKey };
    }
  },

  xai: {
    envKey: 'XAI_API_KEY',
    defaultModel: process.env.XAI_MODEL || 'grok-3-mini-fast',
    endpoint: 'https://api.x.ai/v1/chat/completions',
    formatRequest(prompt, model) {
      return {
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: 'Return valid JSON only.' },
            { role: 'user', content: prompt }
          ]
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    },
    extractText(data) {
      if (data.choices && data.choices[0] && data.choices[0].message) {
        return (data.choices[0].message.content || '').trim();
      }
      return '';
    },
    authHeader(apiKey) {
      return { Authorization: `Bearer ${apiKey}` };
    }
  }
};

function resolveProvider(overrideProvider) {
  const name = (overrideProvider || process.env.LLM_PROVIDER || 'openai').toLowerCase();
  const provider = PROVIDERS[name];
  if (!provider) {
    throw new Error(`Unknown LLM provider "${name}". Supported: ${Object.keys(PROVIDERS).join(', ')}`);
  }
  return { name, ...provider };
}

function stripJsonFences(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith('```')) {
    const lines = trimmed.split('\n');
    lines.shift();
    if (lines.length > 0 && lines[lines.length - 1].trim() === '```') lines.pop();
    return lines.join('\n').trim();
  }
  return trimmed;
}

async function callLLMJson({ prompt, provider: providerOverride, model: modelOverride, toolName = 'agent' }) {
  const provider = resolveProvider(providerOverride);
  const apiKey = process.env[provider.envKey];
  if (!apiKey) {
    throw new Error(`${provider.envKey} is not set. Set it before running the ${toolName}. (provider: ${provider.name})`);
  }

  const model = modelOverride || provider.defaultModel;
  const { body, headers } = provider.formatRequest(prompt, model);

  const response = await fetch(provider.endpoint, {
    method: 'POST',
    headers: { ...headers, ...provider.authHeader(apiKey) },
    body
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`LLM API request failed (${response.status}) [${provider.name}/${model}]: ${errorText}`);
  }

  const data = await response.json();
  const text = provider.extractText(data);

  if (!text) {
    throw new Error(`LLM API returned no text output. [${provider.name}/${model}]`);
  }

  const cleaned = stripJsonFences(text);

  try {
    return JSON.parse(cleaned);
  } catch (error) {
    try {
      return Function('"use strict"; return (' + cleaned + ');')();
    } catch (fallbackError) {
      throw new Error(`Failed to parse JSON output from ${provider.name}: ${error.message}\nRaw output:\n${text}`);
    }
  }
}

const DEFAULT_MODEL = resolveProvider().defaultModel;

function extractOutputText(data) {
  return resolveProvider().extractText(data);
}

module.exports = {
  DEFAULT_MODEL,
  callLLMJson,
  callOpenAIJson: callLLMJson,
  extractOutputText,
  resolveProvider,
  PROVIDERS
};
