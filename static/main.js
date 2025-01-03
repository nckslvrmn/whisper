function postSecretFile(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const file = document.getElementById('file').files[0];
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', file.type);

  if ((file.size / 1024 / 1024) > 5) {
    setResp('processing', 'Processing upload', true);
  }

  _encrypt('/encrypt_file', formData, {});
}


function postSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const formData = new FormData(document.getElementById("form")).entries();

  _encrypt('/encrypt', JSON.stringify(Object.fromEntries(formData)), { 'Content-Type': 'application/json' });
}

function _encrypt(route, data, headers) {
  fetch(route, {
    method: 'post',
    headers: headers,
    body: data
  })
    .then(
      function (resp) {
        if (resp.ok) {
          return resp.json();
        } else {
          setResp('alert', 'There was an error storing secret', true);
        }
      }
    )
    .then(
      function (data) {
        const secret_link = `${window.location.origin}/secret/${data.secret_id}`;
        setResp('success', `<br /><a href="${secret_link}" target="_blank">${secret_link}</a><br />passphrase: ${data.passphrase}`, false);
      }
    )
    .catch(() => {
      setResp('alert', 'There was an error storing secret', true);
    });
}

function getSecret(event) {
  event.preventDefault();
  document.getElementById('results').classList.remove('active');

  const formData = new FormData(document.getElementById("form"));
  formData.append('secret_id', window.location.pathname.split('/').slice(-1)[0]);

  fetch('/decrypt', {
    method: 'post',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(Object.fromEntries(formData.entries()))
  })
    .then(
      function (resp) {
        if (!(resp.ok)) {
          if (resp.status === 404) {
            setResp('warning', 'Secret has either already been viewed<br />or your passphrase is incorrect.', false);
          } else {
            setResp('alert', 'There was an error retrieving secret', true);
          }
        } else {
          if (resp.headers.has('Content-Disposition')) {
            return resp.blob().then(
              function (blob) {
                dlBlob(resp.headers.get('Content-Disposition'), blob);
              });
          } else {
            return resp.json().then(
              function (json) {
                setResp('success', json.data, true);
                document.getElementById('form').remove();
              });
          }
        }
      }
    );
}

function dlBlob(cdheader, blob) {
  const parts = cdheader.split(';');
  filename = parts[1].split('=')[1];
  var url = window.URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function setResp(level, content, text_resp) {
  const results = document.getElementById('results');
  results.classList.remove('active');

  const response = document.getElementById('response');
  response.classList.remove('alert', 'alert-danger', 'alert-warning', 'alert-primary');
  response.removeAttribute('role');

  var alert_level = 'success';
  switch (level) {
    case 'alert':
      alert_level = 'danger';
      break;
    case 'warning':
      alert_level = 'warning';
      break;
    case 'processing':
      alert_level = 'alert-primary';
      break;
  }

  response.classList.add('alert', `alert-${alert_level}`);
  response.setAttribute('role', 'alert');

  if (text_resp) {
    document.getElementById('response_body').innerText = content;
  } else {
    document.getElementById('response_body').innerHTML = content;
  }


  results.classList.add('active');
}
