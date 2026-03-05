'use strict';

function getCookie(cookieHeaders, name) {
  if (!cookieHeaders) return null;

  for (const header of cookieHeaders) {
    const value = header.value || '';
    const pairs = value.split(';');
    for (const pair of pairs) {
      const [key, ...rest] = pair.trim().split('=');
      if (key && key.trim() === name) {
        return rest.join('=').trim();
      }
    }
  }

  return null;
}

module.exports = { getCookie };
