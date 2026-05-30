import os
from fake_useragent import UserAgent

HTTP_TIMEOUT_SECONDS = 2.0
BROWSER_TIMEOUT_MS = 5_000
MAX_REDIRECTS = 5
MAX_SUBDOMAINS = 4
MAX_BODY_BYTES = 4096
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
)

def _generate_user_agent() -> str:
    try:
        return UserAgent(
            platforms="desktop",
            browsers=["Chrome", "Edge"],
            fallback=DEFAULT_USER_AGENT,
        ).random
    except Exception:
        return DEFAULT_USER_AGENT

USER_AGENT = os.getenv("DYNAMIC_URL_SCANNER_USER_AGENT") or _generate_user_agent()

ZERO_WIDTH_OR_INVISIBLE = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
    "snip.ly",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
    "t.ly",
    "tbit.be",
    "trib.al",
}

BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "google": ("google.com", "google.co.il"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "office365.com"),
    "apple": ("apple.com",),
    "amazon": ("amazon.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "leumi": ("leumi.co.il",),
    "hapoalim": ("bankhapoalim.co.il",),
    "mizrahi": ("mizrahi-tefahot.co.il",),
    "discount": ("discountbank.co.il",),
    "isracard": ("isracard.co.il",),
    "max": ("max.co.il",),
    "cal": ("cal-online.co.il",),
    "israelpost": ("israelpost.co.il",),
    "gov": ("gov.il",),
}

CONFUSABLE_CODEPOINTS = {
    # Common Cyrillic/Greek characters that visually overlap Latin characters.
    "\u0430",  # Cyrillic small a
    "\u0435",  # Cyrillic small ie
    "\u043e",  # Cyrillic small o
    "\u0440",  # Cyrillic small er
    "\u0441",  # Cyrillic small es
    "\u0445",  # Cyrillic small ha
    "\u0443",  # Cyrillic small u
    "\u0456",  # Cyrillic small byelorussian-ukrainian i
    "\u03bf",  # Greek small omicron
    "\u03c1",  # Greek small rho
    "\u03bd",  # Greek small nu
}

def browser_enabled() -> bool:
    return os.getenv("DYNAMIC_URL_SCANNER_ENABLE_BROWSER", "").strip().lower() == "true"
