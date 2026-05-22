import hashlib
import requests


def check_password_leak(password: str) -> str:
    """
    Check a password against HaveIBeenPwned using the k-anonymity model.
    Only the first 5 characters of the SHA-1 hash are sent — the full password never leaves your machine.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        return f"[WARN] Could not reach HIBP API: {e}"

    for line in response.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return f"[WARNING] This password was found in {count} data breaches!"

    return "[SAFE] This password was not found in any known breaches."


if __name__ == "__main__":
    print(check_password_leak("123456"))
