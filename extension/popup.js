document.addEventListener('DOMContentLoaded', function() {
  const phishing = document.getElementById('phishing');

    // Retrieve and set the checkbox state from storage when the popup opens
    chrome.storage.local.get(['checkboxState'], function (result) {
        if (result.checkboxState !== undefined) {
            phishing.checked = result.checkboxState;
        }
    });

    phishing.addEventListener('change', function () {
        // Save the checkbox state to storage when it changes
        chrome.storage.local.set({ checkboxState: phishing.checked }, function () {
            console.log('Checkbox state saved:', phishing.checked);
        });
    });

    // check if currently is checking website
    chrome.storage.local.get(['isChecking'], function (result) {
        if (result.isChecking) {
            document.getElementById("check").style.display = "block"
            document.getElementById("bad").style.display = "none"
            document.getElementById("good").style.display = "none"
        }
        else document.getElementById("check").style.display = "none"
    });

    chrome.storage.local.get(['good'], function (result) {
        if (result.good) document.getElementById("good").style.display = "block"
        else document.getElementById("good").style.display = "none"
    });
    chrome.storage.local.get(['bad'], function (result) {
        if (result.bad) document.getElementById("bad").style.display = "block"
        else document.getElementById("bad").style.display = "none"
    });
});