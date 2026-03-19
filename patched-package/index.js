'use strict';

function getProtocol(rawUrl) {
  return new URL(rawUrl).protocol;
}

function isAllowedProtocol(rawUrl, allowedProtocols) {
  return allowedProtocols.includes(getProtocol(rawUrl));
}

function request(options) {
  const config = Object.assign(
    {
      url: '',
      redirects: [],
      allowedProtocols: ['https:']
    },
    options || {}
  );

  if (!isAllowedProtocol(config.url, config.allowedProtocols)) {
    return {
      ok: false,
      blocked: true,
      reason: 'initial protocol blocked',
      finalUrl: config.url
    };
  }

  let current = config.url;

  for (const redirectUrl of config.redirects) {
    if (!isAllowedProtocol(redirectUrl, config.allowedProtocols)) {
      return {
        ok: false,
        blocked: true,
        reason: 'redirect protocol blocked',
        finalUrl: current,
        blockedUrl: redirectUrl
      };
    }

    current = redirectUrl;
  }

  return {
    ok: true,
    blocked: false,
    finalUrl: current
  };
}

module.exports = request;
