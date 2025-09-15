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

  // Start the Go program (standard Go WASM keeps running with select{})
  go.run(result.instance);
  
  // Wait a moment for initialization to complete
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // wasmCrypto should be set by the WASM module
  wasmCrypto = window.wasmCrypto;
  
  if (!wasmCrypto) {
    throw new Error('WASM crypto module failed to initialize');
  }
  
  wasmReady = true;
}

async function postSecretFile(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const file = document.getElementById('file').files[0];
  if (!file) {
    setResp('warning', 'Please select a file', true);
    return;
  }

  const MAX_FILE_SIZE_MB = 5;
  if ((file.size / (1024 * 1024)) > MAX_FILE_SIZE_MB) {
    setResp('warning', 'File size exceeds 5MB limit', true);
    return;
  }

  try {
    await initWASM();
    setResp('processing', 'Encrypting file...', true);

    // Convert file to base64
    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const base64 = btoa(String.fromCharCode(...bytes));

    const result = wasmCrypto.encryptFile(base64, file.name, file.type);

    if (result.error) {
      throw new Error(result.error);
    }

    // Store encrypted file on server
    const response = await fetch('/encrypt_file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        passwordHash: result.passwordHash,
        encryptedData: result.encryptedMetadata,
        encryptedFile: result.encryptedFile,
        encryptedMetadata: result.encryptedMetadata,
        nonce: result.nonce,
        salt: result.salt,
        header: result.header,
        viewCount: result.viewCount,
        ttl: result.ttl,
        isFile: true
      })
    });

    if (!response.ok) {
      throw new Error('Failed to store encrypted file');
    }

    const responseData = await response.json();
    const secret_link = `${window.location.origin}/secret/${responseData.secretId}`;
    setResp('success',
      `<a href="${secret_link}" target="_blank">${secret_link}</a><br/>
       Passphrase: <code>${result.passphrase}</code>`,
      false);
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', 'There was an error encrypting the file', true);
  }
}

async function postSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const form = document.getElementById("form");
  if (!form) {
    setResp('alert', 'Form not found', true);
    return;
  }

  try {
    await initWASM();
    setResp('processing', 'Encrypting data...', true);

    const formData = new FormData(form);
    const secret = formData.get('secret');
    const viewCount = formData.get('view_count') || '1';
    const ttlDays = formData.get('ttl_days') || '7';

    if (!secret) {
      setResp('warning', 'Please enter a secret', true);
      return;
    }

    const result = wasmCrypto.encryptText(secret, viewCount, ttlDays);

    if (result.error) {
      throw new Error(result.error);
    }

    // Store encrypted data on server
    const response = await fetch('/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        passwordHash: result.passwordHash,
        encryptedData: result.encryptedData,
        nonce: result.nonce,
        salt: result.salt,
        header: result.header,
        viewCount: result.viewCount,
        ttl: result.ttl,
        isFile: false
      })
    });

    if (!response.ok) {
      throw new Error('Failed to store encrypted data');
    }

    const responseData = await response.json();
    const secret_link = `${window.location.origin}/secret/${responseData.secretId}`;
    setResp('success',
      `<a href="${secret_link}" target="_blank">${secret_link}</a><br/>
       Passphrase: <code>${result.passphrase}</code>`,
      false);
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', 'There was an error encrypting the secret', true);
  }
}

async function getSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const formData = new FormData(document.getElementById("form"));
  const passphrase = formData.get('passphrase');
  const secretId = window.location.pathname.split('/').slice(-1)[0];

  if (!passphrase) {
    setResp('warning', 'Please enter the passphrase', true);
    return;
  }

  try {
    await initWASM();
    setResp('processing', 'Decrypting...', true);

    // First, get the salt from the server
    let saltResponse = await fetch('/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret_id: secretId,
        getSalt: true
      })
    });

    if (!saltResponse.ok) {
      setResp('warning', 'Secret not found', true);
      return;
    }

    const saltData = await saltResponse.json();

    // Generate password hash using the correct salt
    const passwordHash = wasmCrypto.hashPassword(passphrase, saltData.salt);

    // Now fetch the encrypted data with the correct password hash
    let response = await fetch('/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret_id: secretId,
        passwordHash: passwordHash
      })
    });

    if (!response.ok && response.status === 401) {
      setResp('warning', 'Invalid passphrase', true);
      return;
    }

    if (!response.ok) {
      if (response.status === 404) {
        setResp('warning', 'Secret not found or already viewed', true);
      } else {
        setResp('alert', 'There was an error retrieving the secret', true);
      }
      return;
    }

    const data = await response.json();

    if (data.isFile) {
      // Decrypt file
      const result = wasmCrypto.decryptFile(
        data.encryptedFile,
        data.encryptedMetadata,
        passphrase,
        data.nonce,
        data.salt,
        data.header
      );

      if (result.error) {
        throw new Error(result.error);
      }

      // Convert base64 back to blob
      const binaryString = atob(result.fileData);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: result.fileType });

      // Create download link
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
      // Decrypt text
      const result = wasmCrypto.decryptText(
        data.encryptedData,
        passphrase,
        data.nonce,
        data.salt,
        data.header
      );

      if (result.error) {
        throw new Error(result.error);
      }

      setResp('success', result.data, true);
    }

    document.getElementById('form').remove();
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', 'There was an error decrypting the secret', true);
  }
}

function setResp(level, content, text_resp) {
  const results = document.getElementById('results');
  const response = document.getElementById('response');
  const responseBody = document.getElementById('response_body');

  if (!results || !response || !responseBody) {
    console.error('Required DOM elements not found');
    return;
  }

  results.classList.remove('active');
  response.classList.remove('alert', 'alert-danger', 'alert-warning', 'alert-primary');
  response.removeAttribute('role');

  const alertLevels = {
    alert: 'danger',
    warning: 'warning',
    processing: 'primary',
    success: 'success'
  };

  const alertLevel = alertLevels[level] || 'success';
  response.classList.add('alert', `alert-${alertLevel}`);
  response.setAttribute('role', 'alert');

  if (text_resp) {
    responseBody.innerText = content;
  } else {
    responseBody.innerHTML = content;
  }

  results.classList.add('active');
}

function toggleEncryptionType(type) {
  const textForm = document.getElementById('textForm');
  const fileForm = document.getElementById('fileForm');
  const textToggle = document.getElementById('textToggle');
  const fileToggle = document.getElementById('fileToggle');

  if (type === 'text') {
    textForm.style.display = 'block';
    fileForm.style.display = 'none';
    textToggle.classList.remove('btn-outline-primary');
    textToggle.classList.add('btn-primary');
    fileToggle.classList.remove('btn-primary');
    fileToggle.classList.add('btn-outline-primary');

    const fileInput = document.getElementById('file');
    if (fileInput) {
      fileInput.value = '';
    }
  } else {
    textForm.style.display = 'none';
    fileForm.style.display = 'block';
    textToggle.classList.remove('btn-primary');
    textToggle.classList.add('btn-outline-primary');
    fileToggle.classList.remove('btn-outline-primary');
    fileToggle.classList.add('btn-primary');

    const textArea = document.querySelector('#form textarea[name="secret"]');
    if (textArea) {
      textArea.value = '';
    }
  }

  document.getElementById('results').classList.remove('active');
}

window.addEventListener('DOMContentLoaded', async (event) => {
  // Initialize WASM on page load
  try {
    await initWASM();
    console.log('WASM crypto module loaded successfully');
  } catch (error) {
    console.error('Failed to load WASM module:', error);
  }

  // Check URL params for file mode
  const urlParams = new URLSearchParams(window.location.search);
  const type = urlParams.get('type');
  if (type === 'file') {
    toggleEncryptionType('file');
  }
});
