from user_agents import parse


def get_client_ip(request):
    """
    Returns the client's IP address.
    Supports proxies such as Nginx or Cloudflare.
    """

    forwarded = request.headers.get("X-Forwarded-For")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "127.0.0.1"


def parse_user_agent(user_agent_string):
    """
    Extract device type and browser from the User-Agent header.
    """

    if not user_agent_string:
        return "Unknown", "Unknown"

    ua = parse(user_agent_string)

    if ua.is_mobile:
        device = "Mobile"
    elif ua.is_tablet:
        device = "Tablet"
    elif ua.is_pc:
        device = "Desktop"
    else:
        device = "Other"

    browser = ua.browser.family

    return device, browser


def mock_geolocation(ip_address):
    """
    Temporary location lookup.

    Replace this later with a real geolocation API
    such as ipinfo.io or ipapi.co.
    """

    if ip_address in ("127.0.0.1", "::1"):
        return "Localhost"

    return "Nigeria"