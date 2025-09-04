let popupAdCount = {};
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Count popup ads for each tab
    const tabId = details.tabId;
    if (!popupAdCount[tabId]) popupAdCount[tabId] = 0;
    if (details.url.includes("doubleclick.net") || details.url.includes("adservice.google.com") || details.url.includes("ads")) {
      popupAdCount[tabId]++;
      // increase phishing score on many pop up ads
      if (popupAdCount[tabId] > 5) {
        if (phishingTabInfo[tabId]) {
          phishingTabInfo[tabId].score += 10;
          phishingTabInfo[tabId].reasons.push('Many ads/popups detected');
          if (phishingTabInfo[tabId].score > 100) phishingTabInfo[tabId].score = 100;
        }
      }
      return { cancel: false };
    }
    return { cancel: false };
  },
  { urls: ["<all_urls>"] },
  []
);



// =======Pop Up Detection - First Severity Alert=======
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const info = calculatePhishingInfo(tab);
    // Add ad/popup detection to score
    if (popupAdCount[tabId] && popupAdCount[tabId] > 5) {
      info.score += 10;
      info.reasons.push('Many ads/popups detected');
      if (info.score > 100) info.score = 100;
    }
    phishingTabInfo[tabId] = info;
    // Show browser notification if score > 80
    if (info.score > 80) {
      console.log('[EoHGuard] Triggering notification. Score:', info.score, 'Reasons:', info.reasons);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/128.png',
        title: 'Phishing Alert!',
        message: 'This site may be phishing! (' + info.score + '%)\n' + info.reasons.join(', ')
      }, (notificationId) => {
        console.log('[EoHGuard] Notification created with ID:', notificationId);
      });
    }
  }
});



// =======Phishing Detection Logic=======
const phishingTabInfo = {};
function calculatePhishingInfo(tab) {
  let score = 0;
  let reasons = [];
  const url = tab.url || "";
  // Protocol
  if (!url.startsWith('https://')) {
    score += 50;
    reasons.push('Site is not using HTTPS');
  }
  // Contains IP address
  if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url)) {
    score += 20;
    reasons.push('URL contains IP address');
  }
  // Long URL
  if (url.length > 60) {
    score += 10;
    reasons.push('URL is unusually long');
  }
  // Suspicious keywords
  const suspiciousKeywords = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'paypal', 'password', 'signin', 'alert', 'urgent', 'confirm', 'reset'];
  suspiciousKeywords.forEach(keyword => {
    if (url.toLowerCase().includes(keyword)) {
      score += 7;
      reasons.push('Suspicious keyword: ' + keyword);
    }
  });
  // Public/global phishing reports (non completed)
  const blacklist = ['phishingsite.com', 'malicious-site.net', 'badsite.org', 'web.simmons.edu', 'httpforever.com']; // added by me, contains examples
  if (blacklist.some(domain => url.includes(domain))) {
    score += 30;
    reasons.push('Reported phishing site');
  }
  // Weak language (non completed)
  const weakWords = ['clik', 'verfy', 'acount', 'passwrod', 'securty'];
  weakWords.forEach(word => {
    if (url.toLowerCase().includes(word)) {
      score += 5;
      reasons.push('Possible weak language: ' + word);
    }
  });
  // Non-identical domain (lookalike)
  const lookalikePatterns = [
    { real: 'facebook.com', fake: /face[b8][o0]{2}k\.com/ },
    { real: 'google.com', fake: /g[o0]{2}gle\.com/ },
    { real: 'paypal.com', fake: /paypa[l1]\.com/ },
    { real: 'twitter.com', fake: /twitt[e3]r\.com/ }
  ];
  lookalikePatterns.forEach(({ real, fake }) => {
    if (fake.test(url)) {
      score += 25;
      reasons.push('Domain looks like ' + real);
    }
  });

  if (score > 100) score = 100;
  return { score, reasons, url };
}



// =======Phishing detection notifications - Second Severity Alert=======
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const info = calculatePhishingInfo(tab);
    phishingTabInfo[tabId] = info;
    chrome.tabs.sendMessage(tabId, {
      type: 'phishingInfo',
      ...info
    });
    if (info.score > 70) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/128.png',
        title: 'Phishing Warning!',
        message: 'This site may be phishing! (' + info.score + '%)\n' + info.reasons.join(', ')
      });
    }
  }
});




// =======Respond to popup requests=======
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[EoHGuard] onMessage received:', message, sender);
  if (message.type === 'getPhishingInfo' && message.tabId) {
    const tabId = message.tabId;
    if (phishingTabInfo[tabId]) {
      sendResponse({
        type: 'phishingInfo',
        ...phishingTabInfo[tabId]
      });
      return true;
    } else {
      chrome.tabs.get(tabId, tab => {
        if (tab && tab.url) {
          const info = calculatePhishingInfo(tab);
          phishingTabInfo[tabId] = info;
          sendResponse({
            type: 'phishingInfo',
            ...info
          });
        } else {
          sendResponse({ type: 'phishingInfo', score: 0, reasons: [], url: '' });
        }
      });
      return true;
    }
  }
  return true;
});
