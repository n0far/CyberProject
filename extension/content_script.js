const checkPhishing = async  () => {
  chrome.storage.local.set({ isChecking: true }, function () {
    console.log('Checkbox state saved:', true);
  });

  const url = window.location.href;

  const response = await chrome.runtime.sendMessage({ type: 'phishing', url });

  if (response === 'NONE') {
    chrome.storage.local.set({ good: true });
    chrome.storage.local.set({ bad: false });
    return;
  }
  chrome.storage.local.set({ bad: true });
  chrome.storage.local.set({ good: false });

  document.body = document.createElement('body');
  for (let i = 0; i < document.styleSheets.length; i++) {
    document.styleSheets.item(i).disabled = true;
  }
  document.body.insertAdjacentHTML('afterbegin', await chrome.runtime.sendMessage({ type: 'page-phishing' }))
  const reason = document.createElement("h2");
  document.body.querySelector("#reason").insertAdjacentElement("beforeend", reason)

  if (response === 'DOMAIN') {
    reason.textContent = "The URL is suspicious"
  }
  else if (response === 'DNS') {
    reason.textContent = "The DNS Information is suspicious"
  }
  else if (response === 'HTML') {
    reason.textContent = "The HTML and JS are suspicious"
  }
  
}

window.onload = async () => {
  chrome.storage.local.set({ bad: false });
  chrome.storage.local.set({ good: false });
  chrome.storage.local.get(['checkboxState'], async (result) => {
    if (result.checkboxState) await checkPhishing();
    chrome.storage.local.set({ isChecking: false });
  });
}