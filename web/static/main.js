const TIMEOUTS = {
  WASM_INIT: 100,
  FADE_TRANSITION: 200,
  FORM_REMOVE: 300,
  COPY_RESET: 2000,
  FOCUS_DELAY: 100
};

let wasmReady = false;
let wasmCrypto = null;
async function initWASM() {
  if (wasmReady) return;

  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(
    fetch('/static/crypto.wasm'),
    go.importObject
  );

  go.run(result.instance);
  await new Promise(resolve => setTimeout(resolve, TIMEOUTS.WASM_INIT));

  wasmCrypto = window.wasmCrypto;
  if (!wasmCrypto) {
    throw new Error('WASM crypto module failed to initialize');
  }

  wasmReady = true;
}

function getTTLConfig(disableTTLId, disableViewCountId, exactTTLId, defaultViewCount = '1', defaultTTLDays = '7') {
  let viewCount = defaultViewCount;
  let ttlDays = defaultTTLDays;
  let ttlTimestamp = null;

  const disableTTLElem = document.getElementById(disableTTLId);
  const disableViewCountElem = document.getElementById(disableViewCountId);
  const exactTTLElem = document.getElementById(exactTTLId);

  if (disableTTLElem && disableViewCountElem && exactTTLElem) {
    const disableTTL = disableTTLElem.checked;
    const disableViewCount = disableViewCountElem.checked;
    const exactTTL = exactTTLElem.value;

    if (disableViewCount) {
      viewCount = null;
    }

    if (exactTTL) {
      const selectedDate = new Date(exactTTL);
      ttlTimestamp = Math.floor(selectedDate.getTime() / 1000).toString();
      ttlDays = null;
    } else if (disableTTL) {
      ttlDays = null;
      ttlTimestamp = null;
    }
  }

  return { viewCount, ttlDays, ttlTimestamp };
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.slice(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToBlob(base64, type) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return new Blob([bytes], { type });
}

async function postJSON(url, data) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error('Unauthorized');
    if (response.status === 404) throw new Error('NotFound');
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json();
}

async function handleEncryption(encryptFn, endpoint, extraData = {}) {
  const submitBtn = extraData.isFile ? document.getElementById('submitBtnFile') : document.getElementById('submitBtn');
  const submitBtnText = extraData.isFile ? document.getElementById('submitBtnFileText') : document.getElementById('submitBtnText');
  let infoToast = null;

  try {
    await initWASM();

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtnText.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Encrypting...';
    }

    infoToast = toast.open({
      type: 'info',
      message: 'Encrypting your secret...'
    });

    const result = encryptFn();
    if (result.error) throw new Error(result.error);

    const responseData = await postJSON(endpoint, {
      passwordHash: result.passwordHash,
      encryptedData: result.encryptedData || result.encryptedMetadata,
      nonce: result.nonce,
      salt: result.salt,
      header: result.header,
      viewCount: result.viewCount,
      ttl: result.ttl,
      ...extraData,
      ...(result.encryptedFile && { encryptedFile: result.encryptedFile, encryptedMetadata: result.encryptedMetadata })
    });

    if (infoToast) toast.dismiss(infoToast);

    const secret_link = `${window.location.origin}/secret/${responseData.secretId}`;
    const contentId = 'secretContent_' + Date.now();

    setResp('success',
      `<span class="checkmark">✓</span> <strong>Secret successfully stored</strong><br/><br/><div id="${contentId}"><a href="${secret_link}" target="_blank">${secret_link}</a><br/><br/>Passphrase: <code>${result.passphrase}</code></div>
      <button class="copy-btn-float" onclick="copyToClipboard('${contentId}', this)" aria-label="Copy link and passphrase">
        <i class="fas fa-copy"></i> Copy
      </button>`,
      false);

    clearForm(extraData.isFile);
    scrollToResults();

    toast.success('Secret created successfully!');
  } catch (error) {
    console.error('Error:', error);
    if (infoToast) toast.dismiss(infoToast);
    toast.error(`Failed to encrypt ${extraData.isFile ? 'file' : 'secret'}`);

  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtnText.textContent = 'Create Secret Link';
    }
  }
}

async function postSecretFile(event) {
  event.preventDefault();

  const file = document.getElementById('file').files[0];
  if (!file) {
    toast.error('Please select a file');
    return;
  }

  if ((file.size / (1024 * 1024)) > 10) {
    toast.error('File size exceeds 10MB limit');
    return;
  }

  const { viewCount, ttlDays, ttlTimestamp } = getTTLConfig(
    'disableTTLFile',
    'disableViewCountFile',
    'exactTTLFile'
  );

  const arrayBuffer = await file.arrayBuffer();
  const base64 = arrayBufferToBase64(arrayBuffer);

  await handleEncryption(
    () => wasmCrypto.encryptFile(base64, file.name, file.type, viewCount, ttlDays, ttlTimestamp),
    '/encrypt_file',
    { isFile: true }
  );
}

async function postSecret(event) {
  event.preventDefault();

  const form = document.getElementById("form");
  if (!form) {
    toast.error('Form not found');
    return;
  }

  const formData = new FormData(form);
  const secret = formData.get('secret');

  if (!secret) {
    toast.error('Please enter a secret');
    return;
  }

  const { viewCount, ttlDays, ttlTimestamp } = getTTLConfig(
    'disableTTL',
    'disableViewCount',
    'exactTTL',
    formData.get('view_count') || '1',
    formData.get('ttl_days') || '7'
  );

  await handleEncryption(
    () => wasmCrypto.encryptText(secret, viewCount, ttlDays, ttlTimestamp),
    '/encrypt',
    { isFile: false }
  );
}

async function getSecret(event) {
  event.preventDefault();

  const formData = new FormData(document.getElementById("form"));
  const passphrase = formData.get('passphrase');
  const secretId = window.location.pathname.split('/').pop();

  if (!passphrase) {
    toast.error('Please enter the passphrase');
    return;
  }

  const form = document.getElementById('form');
  let infoToast = null;

  try {
    await initWASM();
    infoToast = toast.open({
      type: 'info',
      message: 'Decrypting your secret...'
    });
    scrollToResults();

    const saltData = await postJSON('/decrypt', {
      secret_id: secretId,
      getSalt: true
    }).catch(() => {
      throw new Error('Secret not found or already viewed');
    });

    const passwordHash = wasmCrypto.hashPassword(passphrase, saltData.salt);
    const data = await postJSON('/decrypt', {
      secret_id: secretId,
      passwordHash: passwordHash
    }).catch(err => {
      if (err.message === 'NotFound') throw new Error('Secret not found or already viewed');
      throw new Error('Error retrieving the secret');
    });

    if (infoToast) toast.dismiss(infoToast);

    if (data.isFile) {
      const result = wasmCrypto.decryptFile(
        data.encryptedFile,
        data.encryptedMetadata,
        passphrase,
        data.nonce,
        data.salt,
        data.header
      );

      if (result.error) throw new Error(result.error);

      const blob = base64ToBlob(result.fileData, result.fileType);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), TIMEOUTS.FOCUS_DELAY);

      setResp('success', `<span class="checkmark">✓</span> File "${result.fileName}" downloaded successfully`, false);
      toast.success('File downloaded successfully');
    } else {
      const result = wasmCrypto.decryptText(
        data.encryptedData,
        passphrase,
        data.nonce,
        data.salt,
        data.header
      );

      if (result.error) throw new Error(result.error);
      const contentId = 'decryptedContent_' + Date.now();
      setResp('success', `<span class="checkmark">✓</span> <strong>Decrypted Secret:</strong><br/><br/><div id="${contentId}">${result.data}</div>
      <button class="copy-btn-float" onclick="copyToClipboard('${contentId}', this)" aria-label="Copy decrypted secret">
        <i class="fas fa-copy"></i> Copy
      </button>`, false);
      scrollToResults();
      toast.success('Secret decrypted successfully!');
    }

    if (form) {
      form.classList.add('fade');
      form.classList.remove('show');
      setTimeout(() => form.remove(), TIMEOUTS.FORM_REMOVE);
    }
  } catch (error) {
    console.error('Error:', error);
    if (infoToast) toast.dismiss(infoToast);
    const message = error.message.includes('passphrase') ? 'Invalid passphrase' :
      error.message.includes('not found') ? error.message :
        'There was an error decrypting the secret';
    toast.error(message);
  }
}

function setResp(level, content, text_resp) {
  const results = document.getElementById('results');
  const response = document.getElementById('response');
  const responseBody = document.getElementById('response_body');

  if (!results || !response || !responseBody) {
    return console.error('Required DOM elements not found');
  }

  const newClass = 'alert alert-' + {
    alert: 'danger',
    warning: 'warning',
    processing: 'primary',
    success: 'success'
  }[level] || 'success';

  const isAlreadyActive = results.classList.contains('active');

  if (isAlreadyActive) {
    responseBody.classList.add('fade');
    responseBody.classList.remove('show');

    setTimeout(() => {
      response.className = newClass;
      response.setAttribute('role', 'alert');
      responseBody[text_resp ? 'innerText' : 'innerHTML'] = content;
      responseBody.classList.add('show');
    }, TIMEOUTS.FADE_TRANSITION);
  } else {
    response.className = newClass;
    response.setAttribute('role', 'alert');
    responseBody[text_resp ? 'innerText' : 'innerHTML'] = content;

    requestAnimationFrame(() => {
      results.classList.add('active');
    });
  }
}

function scrollToResults() {
  const results = document.getElementById('results');
  if (results) {
    const formWrapper = document.querySelector('.form');
    if (formWrapper) {
      formWrapper.style.marginBottom = '5vh';
    }

    const handleTransitionEnd = () => {
      window.scrollTo({
        top: document.documentElement.scrollHeight,
        behavior: 'smooth'
      });
      results.removeEventListener('transitionend', handleTransitionEnd);
    };

    results.addEventListener('transitionend', handleTransitionEnd);
  }
}

function copyToClipboard(elementId, button) {
  const element = document.getElementById(elementId);
  if (!element) return;

  let text = element.textContent || element.innerText;
  text = text.replace("Passphrase:", "\nPassphrase:");

  navigator.clipboard.writeText(text).then(() => {
    const originalHTML = button.innerHTML;

    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
    button.classList.add('copied');
    button.style.transform = 'scale(1.05)';

    toast.success('Copied to clipboard!');

    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.classList.remove('copied');
      button.style.transform = '';
    }, TIMEOUTS.COPY_RESET);
  }).catch(err => {
    console.error('Failed to copy:', err);
    button.innerHTML = '<i class="fas fa-times"></i> Failed';
    toast.error('Failed to copy to clipboard');

    setTimeout(() => {
      button.innerHTML = '<i class="fas fa-copy"></i> Copy';
    }, TIMEOUTS.COPY_RESET);
  });
}

function clearForm(isFile) {
  if (isFile) {
    const fileInput = document.getElementById('file');
    if (fileInput) fileInput.value = '';
  } else {
    const textarea = document.getElementById('secretText');
    if (textarea) textarea.value = '';
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  try {
    await initWASM();
    console.log('WASM crypto module loaded successfully');
  } catch (error) {
    console.error('Failed to load WASM module:', error);
  }

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('type') === 'file') {
    const fileTab = new bootstrap.Tab(document.getElementById('file-tab'));
    fileTab.show();
  }

  const textarea = document.getElementById('secretText');
  if (textarea) {
    setTimeout(() => textarea.focus(), TIMEOUTS.FOCUS_DELAY);
  }

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const textarea = document.getElementById('secretText');
      if (textarea && textarea.offsetParent !== null) {
        textarea.focus();
      }
    }
  });
});
