(() => {
  function redirect() {
    window.location.href = '/parse.html';
  }

  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(redirect, 150);
  });
})();
