function logout() {
    fetch('/logout', { method: 'GET', credentials: 'include' })
      .then(() => window.location.href = '../templates/login.html')
      .catch(err => console.error('Logout error:', err));
  }