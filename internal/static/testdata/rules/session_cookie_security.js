function handler(req, res, token) {
  // ruleid: sift.session-cookie-no-httponly
  res.cookie('session', token);
  // ruleid: sift.session-cookie-no-httponly
  res.cookie('session', token, { secure: true });
  // ok: sift.session-cookie-no-httponly
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
}
