'use strict';

(function () {
  const notyf = new window.Notyf({
    duration: 6000,
    position: { x: 'right', y: 'top' },
    dismissible: true,
    types: [
      {
        type: 'warning',
        className: 'notyf__toast--warning',
        backgroundColor: '#d97706'
      },
      {
        type: 'info',
        className: 'notyf__toast--info',
        backgroundColor: '#2563eb'
      },
      {
        type: 'custom',
        className: 'notyf__toast--custom',
        backgroundColor: '#4f46e5'
      }
    ]
  });

  function escapeHTML(value) {
    return value.replace(/[&<>"']/g, character => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[character]);
  }

  function show(type, message, options = {}) {
    if (message === undefined || message === null || String(message).trim() === '') return;
    const notification = { ...options, message: escapeHTML(String(message)) };
    if (type === 'error' || type === 'success') {
      return notyf[type](notification);
    }
    return notyf.open({ ...notification, type });
  }

  window.vaultNotify = Object.freeze({
    error: (message, options) => show('error', message, options),
    warning: (message, options) => show('warning', message, options),
    success: (message, options) => show('success', message, options),
    info: (message, options) => show('info', message, options),
    custom: (message, options) => show('custom', message, options)
  });

  const lastMessages = new WeakMap();
  const notices = document.querySelectorAll('.notice[role]');
  notices.forEach(notice => lastMessages.set(notice, notificationKey(notice)));

  function notificationKey(notice) {
    const type = notice.dataset.notyfType || notice.getAttribute('role');
    return `${type}\0${notice.textContent.trim()}`;
  }

  function notifyLegacyNotice(notice) {
    const message = notice.textContent.trim();
    if (!message) {
      lastMessages.delete(notice);
      return;
    }
    const key = notificationKey(notice);
    if (lastMessages.get(notice) === key) return;
    lastMessages.set(notice, key);

    const type = notice.dataset.notyfType || ({
      alert: 'error',
      status: 'info',
      note: 'warning'
    })[notice.getAttribute('role')] || 'error';
    const notify = window.vaultNotify[type] || window.vaultNotify.custom;
    notify(message);
  }

  const observer = new MutationObserver(records => {
    const changedNotices = new Set();
    records.forEach(record => {
      let element = record.target.nodeType === Node.ELEMENT_NODE
        ? record.target
        : record.target.parentElement;
      while (element && element !== document.body) {
        if (element.matches('.notice[role]')) {
          changedNotices.add(element);
          break;
        }
        element = element.parentElement;
      }
    });
    changedNotices.forEach(notifyLegacyNotice);
  });
  observer.observe(document.body, {
    attributes: true,
    attributeFilter: ['data-notyf-type'],
    childList: true,
    characterData: true,
    subtree: true
  });
})();
