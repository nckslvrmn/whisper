function postSecretFile(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const file = document.getElementById('file').files[0];
  if (!file) {
    setResp('warning', 'Please select a file', true);
    return;
  }

  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', file.type);

  const MAX_FILE_SIZE_MB = 5;
  if ((file.size / (1024 * 1024)) > MAX_FILE_SIZE_MB) {
    setResp('processing', 'Processing upload', true);
  }

  _encrypt('/encrypt_file', formData, {});
}

function postSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const form = document.getElementById("form");
  if (!form) {
    setResp('alert', 'Form not found', true);
    return;
  }

  const formData = new FormData(form).entries();
  _encrypt('/encrypt', JSON.stringify(Object.fromEntries(formData)), { 'Content-Type': 'application/json' });
}

async function _encrypt(route, data, headers) {
  try {
    const resp = await fetch(route, {
      method: 'POST',
      headers,
      body: data
    });

    if (!resp.ok) {
      throw new Error('Network response was not ok');
    }

    const responseData = await resp.json();
    const secret_link = `${window.location.origin}/secret/${responseData.secret_id}`;
    setResp('success', `<a href="${secret_link}" target="_blank">${secret_link}</a><br />passphrase: ${responseData.passphrase}`, false);
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', 'There was an error storing secret', true);
  }
}

async function getSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const formData = new FormData(document.getElementById("form"));
  formData.append('secret_id', window.location.pathname.split('/').slice(-1)[0]);

  try {
    const resp = await fetch('/decrypt', {
      method: 'post',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(Object.fromEntries(formData.entries()))
    });

    if (!resp.ok) {
      if (resp.status === 404) {
        setResp('warning', 'Secret has either already been viewed<br />or your passphrase is incorrect.', false);
      } else {
        setResp('alert', 'There was an error retrieving secret', true);
      }
      return;
    }

    if (resp.headers.has('Content-Disposition')) {
      // For file downloads, create a link that opens in a new tab
      const filename = resp.headers.get('Content-Disposition')
        .split(';')
        .find(n => n.includes('filename='))
        ?.split('=')[1]
        ?.trim() || 'download';

      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);

      // Create a link and click it to start the download
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();

      // Clean up
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);

      document.getElementById('form').remove();
    } else {
      const json = await resp.json();
      setResp('success', json.data, true);
      document.getElementById('form').remove();
    }
  } catch (error) {
    console.error('Error:', error);
    setResp('alert', 'There was an error retrieving secret', true);
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
