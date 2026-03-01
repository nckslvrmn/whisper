window.toast = {
  _show: function (type, message, duration = 5000) {
    const template = document.getElementById('toastTemplate');
    const toastEl = template.cloneNode(true);
    toastEl.removeAttribute('id');

    const icon = toastEl.querySelector('.toast-icon');
    const messageEl = toastEl.querySelector('.toast-message');

    if (type === 'success') {
      icon.className = 'fas fa-check toast-icon me-2';
      toastEl.style.backgroundColor = 'var(--cyan)';
    } else if (type === 'error') {
      icon.className = 'fas fa-exclamation-triangle toast-icon me-2';
      toastEl.style.backgroundColor = 'var(--red)';
    } else if (type === 'info') {
      icon.className = 'fas fa-spinner fa-spin toast-icon me-2';
      toastEl.style.backgroundColor = 'var(--purple)';
    }

    messageEl.textContent = message;

    const container = document.querySelector('.toast-container');
    container.appendChild(toastEl);

    const bsToast = new bootstrap.Toast(toastEl, {
      delay: duration,
      autohide: type !== 'info'
    });
    bsToast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
      toastEl.remove();
    });

    return toastEl;
  },
  success: function (message) {
    return this._show('success', message);
  },
  error: function (message) {
    return this._show('error', message);
  },
  open: function (config) {
    return this._show(config.type, config.message, config.duration || 5000);
  },
  dismiss: function (toastEl) {
    if (toastEl) {
      const bsToast = bootstrap.Toast.getInstance(toastEl);
      if (bsToast) bsToast.hide();
    }
  }
};
