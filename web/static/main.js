// WASM crypto module
let wasmReady = false;
let wasmCrypto = null;

// Initialize WASM module
async function initWASM() {
  if (wasmReady) return;

  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(
    fetch('/static/crypto.wasm'),
    go.importObject
  );

  go.run(result.instance);
  await new Promise(resolve => setTimeout(resolve, 100));

  wasmCrypto = window.wasmCrypto;
  if (!wasmCrypto) {
    throw new Error('WASM crypto module failed to initialize');
  }

  wasmReady = true;
}

// Helper to convert ArrayBuffer to base64
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

// Helper to convert base64 to Blob
function base64ToBlob(base64, type) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return new Blob([bytes], { type });
}

// Helper for fetch requests
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

// Common encryption handler
async function handleEncryption(encryptFn, endpoint, extraData = {}) {
  try {
    await initWASM();
    setResp('processing', 'Encrypting...', true);

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

    const secret_link = `${window.location.origin}/secret/${responseData.secretId}`;
    setResp('success',
      `<a href="${secret_link}" target="_blank">${secret_link}</a><br/>Passphrase: <code>${result.passphrase}</code>`,
      false);
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', `There was an error encrypting the ${extraData.isFile ? 'file' : 'secret'}`, true);
  }
}

async function postSecretFile(event) {
  event.preventDefault();
  // Don't hide the results box - we'll just update its content

  const file = document.getElementById('file').files[0];
  if (!file) {
    return setResp('warning', 'Please select a file', true);
  }

  if ((file.size / (1024 * 1024)) > 5) {
    return setResp('warning', 'File size exceeds 5MB limit', true);
  }

  const arrayBuffer = await file.arrayBuffer();
  const base64 = arrayBufferToBase64(arrayBuffer);

  await handleEncryption(
    () => wasmCrypto.encryptFile(base64, file.name, file.type),
    '/encrypt_file',
    { isFile: true }
  );
}

async function postSecret(event) {
  event.preventDefault();
  // Don't hide the results box - we'll just update its content

  const form = document.getElementById("form");
  if (!form) {
    return setResp('alert', 'Form not found', true);
  }

  const formData = new FormData(form);
  const secret = formData.get('secret');

  if (!secret) {
    return setResp('warning', 'Please enter a secret', true);
  }

  const viewCount = formData.get('view_count') || '1';
  const ttlDays = formData.get('ttl_days') || '7';

  await handleEncryption(
    () => wasmCrypto.encryptText(secret, viewCount, ttlDays),
    '/encrypt',
    { isFile: false }
  );
}

async function getSecret(event) {
  event.preventDefault();
  // Don't hide the results box - we'll just update its content

  const formData = new FormData(document.getElementById("form"));
  const passphrase = formData.get('passphrase');
  const secretId = window.location.pathname.split('/').pop();

  if (!passphrase) {
    return setResp('warning', 'Please enter the passphrase', true);
  }

  try {
    await initWASM();
    setResp('processing', 'Decrypting...', true);

    // Get salt first
    const saltData = await postJSON('/decrypt', {
      secret_id: secretId,
      getSalt: true
    }).catch(() => {
      throw new Error('Secret not found');
    });

    // Generate password hash and fetch encrypted data
    const passwordHash = wasmCrypto.hashPassword(passphrase, saltData.salt);
    const data = await postJSON('/decrypt', {
      secret_id: secretId,
      passwordHash: passwordHash
    }).catch(err => {
      if (err.message === 'NotFound') throw new Error('Secret not found or already viewed');
      throw new Error('Error retrieving the secret');
    });

    // Decrypt based on type
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

      // Download file
      const blob = base64ToBlob(result.fileData, result.fileType);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);

      setResp('success', `File "${result.fileName}" downloaded successfully`, true);
    } else {
      const result = wasmCrypto.decryptText(
        data.encryptedData,
        passphrase,
        data.nonce,
        data.salt,
        data.header
      );

      if (result.error) throw new Error(result.error);
      setResp('success', result.data, true);
    }

    document.getElementById('form').remove();
  } catch (error) {
    console.error('Error:', error);
    const message = error.message.includes('passphrase') ? 'Invalid passphrase' :
      error.message.includes('not found') ? error.message :
        'There was an error decrypting the secret';
    setResp(error.message.includes('passphrase') || error.message.includes('not found') ? 'warning' : 'alert',
      message, true);
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

  // If already showing an alert, just transition the content
  if (results.classList.contains('active')) {
    // Add a fade transition class temporarily
    response.style.transition = 'background-color 0.3s ease, color 0.3s ease';
    response.className = newClass;
    response.setAttribute('role', 'alert');
    responseBody[text_resp ? 'innerText' : 'innerHTML'] = content;
  } else {
    // First time showing, do the full animation
    response.className = newClass;
    response.setAttribute('role', 'alert');
    responseBody[text_resp ? 'innerText' : 'innerHTML'] = content;

    requestAnimationFrame(() => {
      results.classList.add('active');
    });
  }
}

function toggleEncryptionType(type) {
  const elements = {
    textForm: document.getElementById('textForm'),
    fileForm: document.getElementById('fileForm'),
    textToggle: document.getElementById('textToggle'),
    fileToggle: document.getElementById('fileToggle')
  };

  const isText = type === 'text';
  elements.textForm.style.display = isText ? 'block' : 'none';
  elements.fileForm.style.display = isText ? 'none' : 'block';

  elements.textToggle.classList.toggle('btn-primary', isText);
  elements.textToggle.classList.toggle('btn-outline-primary', !isText);
  elements.fileToggle.classList.toggle('btn-primary', !isText);
  elements.fileToggle.classList.toggle('btn-outline-primary', isText);

  // Clear inputs
  const input = isText ?
    document.getElementById('file') :
    document.querySelector('#form textarea[name="secret"]');
  if (input) input.value = '';

  const results = document.getElementById('results');
  if (results) results.classList.remove('active');
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
    toggleEncryptionType('file');
  }
});
