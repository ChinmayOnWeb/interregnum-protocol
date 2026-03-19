'use strict';

require('./env_loader');

const DEFAULT_MODEL = process.env.OPENAI_MODEL || 'gpt-5.4-mini';

async function callOpenAIJson({ prompt, model = DEFAULT_MODEL, toolName = 'agent' }) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error(`OPENAI_API_KEY is not set. Set it before running the ${toolName}.`);
  }

  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      input: [
        {
          role: 'system',
          content: [
            {
              type: 'input_text',
              text: 'Return valid JSON only.'
            }
          ]
        },
        {
          role: 'user',
          content: [
            {
              type: 'input_text',
              text: prompt
            }
          ]
        }
      ]
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenAI API request failed (${response.status}): ${errorText}`);
  }

  const data = await response.json();
  const text = extractOutputText(data);

  if (!text) {
    throw new Error('OpenAI API returned no text output.');
  }

  try {
    return JSON.parse(text);
  } catch (error) {
    try {
      return Function('"use strict"; return (' + text + ');')();
    } catch (fallbackError) {
      throw new Error(`Failed to parse JSON output: ${error.message}\nRaw output:\n${text}`);
    }
  }
}

function extractOutputText(data) {
  if (typeof data.output_text === 'string' && data.output_text.trim() !== '') {
    return data.output_text.trim();
  }

  if (!Array.isArray(data.output)) {
    return '';
  }

  const chunks = [];
  for (const item of data.output) {
    if (!Array.isArray(item.content)) {
      continue;
    }

    for (const content of item.content) {
      if (typeof content.text === 'string') {
        chunks.push(content.text);
      }
    }
  }

  return chunks.join('\n').trim();
}

module.exports = {
  DEFAULT_MODEL,
  callOpenAIJson,
  extractOutputText
};
