function refresh(action) {
  chrome.runtime.sendMessage({action}, status => {
    document.getElementById("status").textContent = chrome.runtime.lastError ? "Host unavailable; coverage is not certified." : JSON.stringify(status, null, 2);
  });
}
document.getElementById("finish").addEventListener("click", () => refresh("finish"));
refresh("status");
