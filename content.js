// Switch between tabs
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

// Listen for phishing info from background.js
function updatePhishingUI(message) {
  console.log('[EoHGuard] updatePhishingUI called with:', message);
  document.getElementById("current-url").textContent = message.url || "";
  document.getElementById("phishing-score").textContent = message.score + "%";
  if (message.score > 70) {
    document.getElementById("phishing-alert").classList.remove("hidden");
  } else {
    document.getElementById("phishing-alert").classList.add("hidden");
  }
  // Certificate info
  try {
    const urlObj = new URL(message.url);
    document.getElementById("certificate").textContent = urlObj.protocol === 'https:' ? "Valid (HTTPS)" : "Invalid (Not HTTPS)";
    // Region info (basic: get TLD)
    const tld = urlObj.hostname.split('.').pop();
    let region = "Unknown";
    const tldMap = { 'de': 'Germany', 'us': 'USA', 'fr': 'France', 'jp': 'Japan', 'ca': 'Canada', 'nl': 'Netherlands', 'sg': 'Singapore', 'uk': 'UK', 'au': 'Australia', 'br': 'Brazil', 'com': 'Global', 'net': 'Global', 'org': 'Global' };
    if (tldMap[tld]) region = tldMap[tld];
    document.getElementById("region").textContent = region;
    console.log('[EoHGuard] Certificate:', document.getElementById("certificate").textContent, 'Region:', region);
  } catch (e) {
    document.getElementById("certificate").textContent = "Unknown";
    document.getElementById("region").textContent = "Unknown";
    console.log('[EoHGuard] Error parsing URL for certificate/region:', e);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[EoHGuard] onMessage received:', message);
  if (message.type === 'phishingInfo') {
    updatePhishingUI(message);
  }
});

// Request phishing info when popup loads
document.addEventListener('DOMContentLoaded', () => {
  console.log('[EoHGuard] Popup DOMContentLoaded');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    console.log('[EoHGuard] Active tab:', tab);
    if (tab) {
      chrome.runtime.sendMessage({ type: 'getPhishingInfo', tabId: tab.id }, (response) => {
        console.log('[EoHGuard] getPhishingInfo response:', response);
        if (response && response.type === 'phishingInfo') {
          updatePhishingUI(response);
        }
      });
    }
  });
});

// Report button
document.getElementById("send-report").addEventListener("click", () => {
  let reportText = document.getElementById("report-text").value;
  if (reportText.trim() !== "") {
    alert("Report sent! Thank you.");
    document.getElementById("report-text").value = "";
  } else {
    alert("Please enter report details.");
  }
});
// VPN button (placeholder, no real VPN here)
document.getElementById("connect-vpn").addEventListener("click", () => {
  const vpnStatus = document.getElementById("vpn-status");
  const vpnBtn = document.getElementById("connect-vpn");
  const serverHolder = document.getElementById("server-holder");
  const serverSpan = document.getElementById("server");
  const countries = ["Germany", "USA", "France", "Japan", "Canada", "Netherlands", "Singapore", "UK", "Australia", "Brazil"];
  if (!vpnStatus.classList.contains("connected")) {
    vpnStatus.textContent = "Connected (Demo)";
    vpnStatus.classList.add("connected");
    vpnStatus.innerHTML = "Ping: 42ms | Speed: 20Mbps";
    vpnBtn.innerText = "Disconnect";
    serverHolder.style.display = "block";
    serverSpan.textContent = countries[Math.floor(Math.random() * countries.length)];
  } else {
    vpnStatus.classList.remove("connected");
    vpnStatus.textContent = "Disconnected";
    vpnBtn.innerText = "Connect";
    serverHolder.style.display = "none";
  }
});
const vpnBtn = document.getElementById('connect-vpn');

  vpnBtn.addEventListener('click', () => {
    vpnBtn.classList.toggle('vpn-on');
    vpnBtn.classList.toggle('vpn-off');
    vpnBtn.textContent = vpnBtn.classList.contains('vpn-on') ? "Disconnect" : "Connect";
  });