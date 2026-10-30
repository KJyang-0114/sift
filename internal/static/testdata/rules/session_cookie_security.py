def view(response, token):
    # ruleid: sift.session-cookie-no-httponly-python
    response.set_cookie("session", token)
    # ruleid: sift.session-cookie-no-httponly-python
    response.set_cookie("session", token, secure=True)
    # ok: sift.session-cookie-no-httponly-python
    response.set_cookie("session", token, secure=True, httponly=True)
