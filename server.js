const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3020;
const BASE_URL =
  process.env.DASHSCOPE_BASE_URL || 'https://dashscope.aliyuncs.com/compatible-mode/v1';
const API_KEY = process.env.DASHSCOPE_API_KEY;
const TEXT_MODEL = process.env.TEXT_MODEL || 'qwen-plus';
const VISION_MODEL = process.env.VISION_MODEL || 'qwen-vl-plus';
const PROMPT_PATH = path.join(__dirname, 'prompt.txt');
const PROMPTS_DIR = path.join(__dirname, 'public', 'prompts');
const SCENARIO_PROMPTS = {
  card: 'CARD_SCENARIO.txt',
  moment: 'MOMENT_SCENARIO.txt'
};

if (!API_KEY) {
  console.warn('DASHSCOPE_API_KEY is missing. Set it in .env before running the server.');
}

app.use(cors());
app.use(
  express.json({
    limit: '10mb'
  })
);
app.use(express.static(path.join(__dirname, 'public')));

function normalizeContent(content) {
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') return part;
        if (part && typeof part === 'object' && typeof part.text === 'string') return part.text;
        return '';
      })
      .filter(Boolean)
      .join('\n')
      .trim();
  }
  return '';
}

function readPrompt() {
  try {
    if (!fs.existsSync(PROMPT_PATH)) return '';
    return fs.readFileSync(PROMPT_PATH, 'utf8').trim();
  } catch (err) {
    console.error('Read prompt error:', err.message);
    return '';
  }
}

function readScenarioPrompt(scenario) {
  const fileName = SCENARIO_PROMPTS[scenario];
  if (fileName) {
    const scenarioPath = path.join(PROMPTS_DIR, fileName);
    try {
      if (fs.existsSync(scenarioPath)) {
        return fs.readFileSync(scenarioPath, 'utf8').trim();
      }
    } catch (err) {
      console.error(`Read scenario prompt error (${scenario}):`, err.message);
    }
  }
  return readPrompt();
}

async function callDashScopeChat(model, messages) {
  const url = `${BASE_URL}/chat/completions`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      model,
      messages
    })
  });

  const result = await response.json();
  if (!response.ok) {
    const errorMessage = result?.error?.message || 'Unexpected response from DashScope';
    throw new Error(errorMessage);
  }

  const reply = normalizeContent(result?.choices?.[0]?.message?.content);
  if (!reply) {
    throw new Error('No reply content returned from DashScope.');
  }
  return reply;
}

app.post('/api/chat/text', async (req, res) => {
  const { text, scenario } = req.body || {};
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Text is required.' });
  }

  try {
    const prompt = readScenarioPrompt(scenario);
    const messages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'user',
        content: [{ type: 'text', text }]
      }
    ];
    const reply = await callDashScopeChat(TEXT_MODEL, messages);
    res.json({ text: reply });
  } catch (err) {
    console.error('Text chat error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/chat/image', async (req, res) => {
  const { text, imageBase64, scenario } = req.body || {};
  const userText = typeof text === 'string' ? text : '';
  const hasImage = Boolean(imageBase64 && typeof imageBase64 === 'string');
  if (!userText && !hasImage) {
    return res.status(400).json({ error: 'Provide text or image.' });
  }

  try {
    const prompt = readScenarioPrompt(scenario);
    const imageUrl =
      imageBase64.startsWith('data:') && imageBase64.includes('base64,')
        ? imageBase64
        : `data:image/png;base64,${imageBase64}`;
    const visionMessages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'system',
        content: [
          {
            type: 'text',
            text:
              'You analyze images and describe factual details briefly in Chinese. Focus on card recognition: identify card color (only 红/蓝/黄/绿), row position (第几排), score, and content.'
          }
        ]
      },
      {
        role: 'user',
        content: [
          {
            type: 'text',
            text:
              '请识别图片中的卡牌信息：颜色（仅限红/蓝/黄/绿）、位置（第几排）、分数、内容。若缺失某项，请标注未知。'
          },
          { type: 'image_url', image_url: { url: imageUrl } }
        ]
      }
    ];
    const imageAnalysis = await callDashScopeChat(VISION_MODEL, visionMessages);

    const combinedPrompt = [
      '以下是用户提供的文字与图片解析结果，请综合回答：',
      `用户文本：${text}`,
      `图片解析：${imageAnalysis}`
    ].join('\n');

    const textMessages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'system',
        content: [{ type: 'text', text: 'You are a helpful assistant that reasons over text and extracted image details.' }]
      },
      {
        role: 'user',
        content: [{ type: 'text', text: combinedPrompt }]
      }
    ];
    const finalReply = await callDashScopeChat(TEXT_MODEL, textMessages);
    res.json({ text: finalReply, imageAnalysis });
  } catch (err) {
    console.error('Image chat error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
