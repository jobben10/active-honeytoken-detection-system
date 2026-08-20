import ipaddress
import json
import urllib.error
import urllib.request


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return True

    try:
        address = ipaddress.ip_address(ip)
        return (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        )
    except ValueError:
        return True


def lookup_ip_intelligence(
    ip: str | None
):
    """
    Enrich an IP address with basic
    geolocation and network information.

    Private/local addresses are handled
    locally and are not sent to an
    external service.
    """

    if not ip:

        return {
            "ip": None,
            "is_private": True,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "organization": None,
            "timezone": None,
            "source": "local"
        }

    if is_private_ip(ip):

        return {
            "ip": ip,
            "is_private": True,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "organization": None,
            "timezone": None,
            "source": "local"
        }

    url = (
        "https://ipwho.is/"
        + ip
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "Active-Honeytoken-Detection-System/1.0"
        }
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        if not data.get("success", True):

            return {
                "ip": ip,
                "is_private": False,
                "country": None,
                "region": None,
                "city": None,
                "isp": None,
                "organization": None,
                "timezone": None,
                "source": "ipwho.is",
                "error":
                    data.get(
                        "message",
                        "Lookup failed"
                    )
            }

        connection = data.get(
            "connection",
            {}
        )

        timezone = data.get(
            "timezone",
            {}
        )

        return {
            "ip": ip,
            "is_private": False,
            "country":
                data.get("country"),
            "country_code":
                data.get("country_code"),
            "region":
                data.get("region"),
            "city":
                data.get("city"),
            "latitude":
                data.get("latitude"),
            "longitude":
                data.get("longitude"),
            "isp":
                connection.get("isp"),
            "organization":
                connection.get("org"),
            "asn":
                connection.get("asn"),
            "timezone":
                timezone.get("id"),
            "source":
                "ipwho.is"
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        return {
            "ip": ip,
            "is_private": False,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "organization": None,
            "timezone": None,
            "source": "ipwho.is",
            "error": str(error)
        }

    except Exception as error:

        return {
            "ip": ip,
            "is_private": False,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "organization": None,
            "timezone": None,
            "source": "ipwho.is",
            "error": str(error)
        }