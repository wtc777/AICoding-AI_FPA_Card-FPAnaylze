// Lightweight parser to extract structured versions from a long text block.
// It is defensive: missing fields will be empty strings, parsing continues.

(() => {
  function safeTrim(str) {
    return (str || '').toString().trim();
  }

  function extractSection(text, label) {
    const pattern = new RegExp(`${label}\\s*[:：]\\s*([\\s\\S]*?)($|\\n\\s*\\w+\\s*[:：])`, 'i');
    const match = text.match(pattern);
    if (match && match[1]) {
      return safeTrim(match[1]);
    }
    return '';
  }

  function parseVersionBlock(block, id) {
    const result = {
      id: id || '',
      title: `Version ${id || ''}`.trim(),
      score: null,
      styleTag: '',
      summary: '',
      body: '',
      highlight: '',
      persona: '',
      dmScript: ''
    };

    const scoreMatch = block.match(/score\s*[:：]\s*(\d+)/i);
    if (scoreMatch) result.score = Number(scoreMatch[1]);

    const styleMatch = block.match(/style\s*[:：]\s*([^\n]+)/i);
    if (styleMatch) result.styleTag = safeTrim(styleMatch[1]);

    const body = extractSection(block, 'Body') || block;
    result.body = safeTrim(body);
    result.summary = safeTrim(result.body.slice(0, 60));

    result.highlight = extractSection(block, 'Highlight Analysis');
    result.persona = extractSection(block, 'Customer Persona');
    result.dmScript = extractSection(block, 'DM Script');

    return result;
  }

  function parseAnalysisResult(text) {
    const raw = safeTrim(text);
    if (!raw) return { originalAnalysis: '', overallComment: '', versions: [] };

    const versionRegex = /Version\s+([A-Z])/gi;
    const segments = [];
    let match;
    let lastIndex = 0;

    while ((match = versionRegex.exec(raw)) !== null) {
      if (match.index > lastIndex) {
        segments.push({ label: 'pre', text: raw.slice(lastIndex, match.index) });
      }
      const id = match[1];
      const nextMatch = versionRegex.exec(raw);
      const end = nextMatch ? nextMatch.index : raw.length;
      segments.push({ label: id, text: raw.slice(match.index, end) });
      if (!nextMatch) break;
      versionRegex.lastIndex = nextMatch.index;
      lastIndex = nextMatch.index;
    }

    if (segments.length === 0) {
      return { originalAnalysis: raw, overallComment: '', versions: [] };
    }

    const versions = [];
    let originalAnalysis = '';
    let overallComment = '';

    segments.forEach((seg) => {
      if (seg.label === 'pre') {
        if (!originalAnalysis) originalAnalysis = safeTrim(seg.text);
      } else {
        const v = parseVersionBlock(seg.text, seg.label);
        versions.push(v);
      }
    });

    const tail = safeTrim(raw.slice(raw.lastIndexOf(versions[versions.length - 1]?.body || '') + (versions[versions.length - 1]?.body || '').length));
    if (tail && tail.length > 10) {
      overallComment = tail;
    }

    return { originalAnalysis, overallComment, versions };
  }

  window.parseAnalysisResult = parseAnalysisResult;
})();
