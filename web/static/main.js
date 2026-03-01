import init, { encryptText, encryptFile, decryptText, decryptFile, hashPassword } from '/static/crypto.js';

// Salt is embedded in the first SALT_B64_LEN characters of the display
// passphrase as URL_SAFE (padded) base64. The rest is the actual passphrase.
// This matches the layout produced by the Rust encryptText/encryptFile exports.
const SALT_B64_LEN = 24;

function splitPassphrase(displayPassphrase) {
  if (displayPassphrase.length < SALT_B64_LEN + 1) {
    throw new Error('Invalid passphrase format');
  }
  return {
    saltB64: displayPassphrase.slice(0, SALT_B64_LEN),
    passphrase: displayPassphrase.slice(SALT_B64_LEN),
  };
}

const TIMEOUTS = {
  FADE_TRANSITION: 200,
  COPY_RESET: 2000,
};

let wasmReady = false;
async function initWASM() {
  if (wasmReady) return;
  await init('/static/crypto_bg.wasm');
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

    // Salt is NOT sent to the server — it is embedded in result.passphrase.
    // The server therefore cannot assist offline Argon2 attacks even if the
    // passwordHash store is fully compromised.
    const responseData = await postJSON(endpoint, {
      passwordHash: result.passwordHash,
      encryptedData: result.encryptedData || result.encryptedMetadata,
      nonce: result.nonce,
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
      `<span class="checkmark">✓</span> <strong>Secret successfully stored</strong>
      <div class="mt-3" id="${contentId}"><a href="${secret_link}" target="_blank">${secret_link}</a>
      <div class="mt-2">Passphrase: <code>${result.passphrase}</code></div></div>
      <button class="copy-btn-float" data-copy-target="${contentId}" aria-label="Copy link and passphrase">
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

  const fileFormData = new FormData(document.getElementById('fileFormElement'));
  const { viewCount, ttlDays, ttlTimestamp } = getTTLConfig(
    'disableTTLFile',
    'disableViewCountFile',
    'exactTTLFile',
    fileFormData.get('view_count') || '1',
    fileFormData.get('ttl_days') || '7'
  );

  const arrayBuffer = await file.arrayBuffer();
  const base64 = arrayBufferToBase64(arrayBuffer);

  await handleEncryption(
    () => encryptFile(base64, file.name, file.type, viewCount, ttlDays, ttlTimestamp),
    '/encrypt_file',
    { isFile: true }
  );
}

async function postSecret(event) {
  event.preventDefault();

  const form = document.getElementById('textFormElement');
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
    () => encryptText(secret, viewCount, ttlDays, ttlTimestamp),
    '/encrypt',
    { isFile: false }
  );
}

async function getSecret(event) {
  event.preventDefault();

  const form = document.getElementById('secretForm');
  const formData = new FormData(form);
  const passphrase = formData.get('passphrase');
  const secretId = window.location.pathname.split('/').pop();

  if (!passphrase) {
    toast.error('Please enter the passphrase');
    return;
  }

  const submitBtn = document.getElementById('secretSubmitBtn');
  const submitBtnText = document.getElementById('secretSubmitBtnText');
  let infoToast = null;

  try {
    await initWASM();

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtnText.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Decrypting...';
    }

    infoToast = toast.open({
      type: 'info',
      message: 'Decrypting your secret...'
    });

    // The display passphrase contains the salt in its first SALT_B64_LEN chars.
    // Split it here so we can authenticate and decrypt in a single server round-trip.
    const { saltB64, passphrase: actualPassphrase } = splitPassphrase(passphrase);
    const passwordHash = hashPassword(actualPassphrase, saltB64);

    const data = await postJSON('/decrypt', {
      secret_id: secretId,
      passwordHash: passwordHash
    }).catch(err => {
      if (err.message === 'NotFound') throw new Error('Secret not found or already viewed');
      throw new Error('Invalid passphrase or secret not found');
    });

    if (infoToast) toast.dismiss(infoToast);

    if (data.isFile) {
      const result = decryptFile(
        data.encryptedFile,
        data.encryptedMetadata,
        actualPassphrase,
        data.nonce,
        saltB64,
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
      setTimeout(() => URL.revokeObjectURL(url), 100);

      const fileNameId = 'downloadedFileName_' + Date.now();
      setResp('success', `<span class="checkmark">✓</span> File "<span id="${fileNameId}"></span>" downloaded successfully`, false);
      const fileNameEl = document.getElementById(fileNameId);
      if (fileNameEl) fileNameEl.textContent = result.fileName;
      toast.success('File downloaded successfully');
    } else {
      const result = decryptText(
        data.encryptedData,
        actualPassphrase,
        data.nonce,
        saltB64,
        data.header
      );

      if (result.error) throw new Error(result.error);
      const contentId = 'decryptedContent_' + Date.now();
      // Set structure via innerHTML but inject the actual secret content via
      // textContent only — prevents XSS if the secret contains HTML or JS.
      setResp('success', `<span class="checkmark">✓</span> <strong>Decrypted Secret:</strong>
      <div class="mt-3" id="${contentId}" style="white-space:pre-wrap"></div>
      <button class="copy-btn-float" data-copy-target="${contentId}" aria-label="Copy decrypted secret">
        <i class="fas fa-copy"></i> Copy
      </button>`, false);
      const contentEl = document.getElementById(contentId);
      if (contentEl) contentEl.textContent = result.data;
      toast.success('Secret decrypted successfully!');
    }

    // Collapse the passphrase form — lock height, force reflow, then animate to 0.
    if (form) {
      const h = form.offsetHeight;
      form.style.height = h + 'px';
      form.style.overflow = 'hidden';
      void form.offsetHeight; // force reflow so browser commits the "from" value
      form.style.transition = 'height 0.35s ease, opacity 0.25s ease, padding 0.3s ease';
      requestAnimationFrame(() => {
        form.style.height = '0';
        form.style.opacity = '0';
        form.style.padding = '0';
      });
      form.addEventListener('transitionend', () => {
        form.style.display = 'none';
      }, { once: true });
    }

    scrollToResults();
  } catch (error) {
    console.error('Error:', error);
    if (infoToast) toast.dismiss(infoToast);
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtnText.textContent = 'Decrypt Secret';
    }
    const msg = error.message;
    const display = (msg.includes('not found') || msg.includes('already viewed'))
      ? msg : 'There was an error decrypting the secret';
    toast.error(display);
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
  setTimeout(() => {
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 350);
}

function copyToClipboard(elementId, button) {
  const element = document.getElementById(elementId);
  if (!element) return;

  let text = element.textContent || element.innerText;
  text = text.replace('Passphrase:', '\nPassphrase:');

  navigator.clipboard.writeText(text).then(() => {
    const originalHTML = button.innerHTML;

    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
    button.classList.add('copied');

    toast.success('Copied to clipboard!');

    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.classList.remove('copied');
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
    if (fileInput) {
      fileInput.value = '';
      const helperText = fileInput.parentElement.querySelector('.form-text');
      if (helperText) {
        helperText.textContent = 'Maximum file size: 10MB';
      }
    }
  } else {
    const textarea = document.getElementById('secretText');
    if (textarea) textarea.value = '';
  }
}

// Event delegation for copy buttons injected via innerHTML — avoids inline onclick
// handlers so the CSP does not need 'unsafe-inline'.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.copy-btn-float[data-copy-target]');
  if (btn) copyToClipboard(btn.dataset.copyTarget, btn);
});

window.addEventListener('DOMContentLoaded', async () => {
  try {
    await initWASM();
  } catch (error) {
    console.error('Failed to load WASM module:', error);
  }

  document.getElementById('textFormElement')?.addEventListener('submit', postSecret);
  document.getElementById('fileFormElement')?.addEventListener('submit', postSecretFile);
  document.getElementById('secretForm')?.addEventListener('submit', getSecret);

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('type') === 'file') {
    const fileTab = new bootstrap.Tab(document.getElementById('file-tab'));
    fileTab.show();
  }

  const fileInput = document.getElementById('file');
  if (fileInput) {
    const helperText = fileInput.parentElement.querySelector('.form-text');
    const originalText = helperText ? helperText.textContent : '';

    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file && helperText) {
        const fileSize = (file.size / 1024).toFixed(2);
        helperText.textContent = `Selected: ${file.name} (${fileSize} KB)`;
      } else if (helperText) {
        helperText.textContent = originalText;
      }
    });
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
