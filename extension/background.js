chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'phishing') {
    fetch(`http://127.0.0.1:5000/phishing`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: request.url
      })
    }).then((res) => res.json()).then(sendResponse)
    return true;
  } else if(request.type === 'page-phishing') {
    fetch(chrome.runtime.getURL("phishing.html")).then((res) => res.text()).then(sendResponse)
    return true;
  } else if(request.type === 'page-popup') {
    fetch(chrome.runtime.getURL("popup.html")).then((res) => res.text()).then(sendResponse)
    return true;
  }
});