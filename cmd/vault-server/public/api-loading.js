(() => {
  const nativeFetch = window.fetch.bind(window);
  const indicator = document.createElement('div');
  const spinner = document.createElement('span');
  const label = document.createElement('span');
  let activeRequests = 0;
  let showTimer;

  indicator.className = 'api-loading-indicator';
  indicator.setAttribute('role', 'status');
  indicator.setAttribute('aria-live', 'polite');
  indicator.setAttribute('aria-hidden', 'true');
  indicator.hidden = true;
  spinner.className = 'api-loading-spinner';
  spinner.setAttribute('aria-hidden', 'true');
  label.textContent = 'Please wait';
  indicator.append(spinner, label);
  document.body.append(indicator);

  function isWebAPI(input) {
    try {
      const requestURL = new URL(input instanceof Request ? input.url : input, location.href);
      return requestURL.origin === location.origin && /^\/(?:api|v1)(?:\/|$)/.test(requestURL.pathname);
    } catch {
      return false;
    }
  }

  function finishRequest() {
    activeRequests -= 1;
    if (activeRequests !== 0) return;
    clearTimeout(showTimer);
    indicator.hidden = true;
    indicator.setAttribute('aria-hidden', 'true');
  }

  window.fetch = (...args) => {
    if (!isWebAPI(args[0])) return nativeFetch(...args);

    activeRequests += 1;
    if (activeRequests === 1) {
      showTimer = window.setTimeout(() => {
        if (activeRequests === 0) return;
        indicator.hidden = false;
        indicator.setAttribute('aria-hidden', 'false');
      }, 120);
    }

    let request;
    try {
      request = nativeFetch(...args);
    } catch (error) {
      finishRequest();
      throw error;
    }
    return request.finally(finishRequest);
  };
})();
