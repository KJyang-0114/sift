function save(accessToken, user) {
  // ruleid: sift.frontend-localStorage
  localStorage.setItem('token', accessToken);
  // ruleid: sift.frontend-localStorage
  sessionStorage.setItem('user', accessToken);
  // ruleid: sift.frontend-localStorage
  localStorage.setItem('auth', JSON.stringify(user));
  // ok: sift.frontend-localStorage
  localStorage.setItem('theme', 'dark');
  // ok: sift.frontend-localStorage
  localStorage.setItem('lastPage', window.location.pathname);
}
