"""Shared taxonomies mapping source-specific labels to common categories.

Every mapping in this module is an explicit, versioned analytical decision.
"""

from __future__ import annotations

SECTOR_HEALTH = "Salud"
SECTOR_PUBLIC = "Administración pública"
SECTOR_EDUCATION = "Educación y ciencia"
SECTOR_FINANCE = "Finanzas"
SECTOR_TECH = "Tecnología e información"
SECTOR_PROFESSIONAL = "Servicios profesionales"
SECTOR_RETAIL = "Comercio y hostelería"
SECTOR_INDUSTRY = "Industria"
SECTOR_CRITICAL = "Infraestructura crítica y energía"
SECTOR_MEDIA = "Medios y entretenimiento"
SECTOR_UNKNOWN = "Otros / Desconocido"

# NAICS code; the first two digits give the top-level sector.
VCDB_NAICS_TO_SECTOR = {
    "11": SECTOR_INDUSTRY,
    "21": SECTOR_CRITICAL,
    "22": SECTOR_CRITICAL,
    "23": SECTOR_INDUSTRY,
    "31": SECTOR_INDUSTRY,
    "32": SECTOR_INDUSTRY,
    "33": SECTOR_INDUSTRY,
    "42": SECTOR_RETAIL,
    "44": SECTOR_RETAIL,
    "45": SECTOR_RETAIL,
    "48": SECTOR_CRITICAL,
    "49": SECTOR_CRITICAL,
    "51": SECTOR_TECH,
    "52": SECTOR_FINANCE,
    "53": SECTOR_PROFESSIONAL,
    "54": SECTOR_PROFESSIONAL,
    "55": SECTOR_PROFESSIONAL,
    "56": SECTOR_PROFESSIONAL,
    "61": SECTOR_EDUCATION,
    "62": SECTOR_HEALTH,
    "71": SECTOR_MEDIA,
    "72": SECTOR_RETAIL,
    "81": SECTOR_UNKNOWN,
    "92": SECTOR_PUBLIC,
}

# First value of receiver_category; 'Corporate Targets' matches by prefix.
EUREPOC_CATEGORY_TO_SECTOR = {
    "State institutions / political system": SECTOR_PUBLIC,
    "International / supranational organization": SECTOR_PUBLIC,
    "Critical infrastructure": SECTOR_CRITICAL,
    "Corporate Targets": SECTOR_PROFESSIONAL,
    "Education": SECTOR_EDUCATION,
    "Science": SECTOR_EDUCATION,
    "Media": SECTOR_MEDIA,
    "Social groups": SECTOR_UNKNOWN,
    "End user(s) / specially protected groups": SECTOR_UNKNOWN,
    "Unknown": SECTOR_UNKNOWN,
    "Other": SECTOR_UNKNOWN,
}

# Inferred from HIBP title, domain and description; first match wins.
HIBP_KEYWORDS_TO_SECTOR = (
    (("bank", "financ", "trading", "crypto", "exchange", "loan", "payment", "invest"), SECTOR_FINANCE),
    (("health", "medical", "pharma", "clinic", "patient"), SECTOR_HEALTH),
    (("university", "school", "educat", "academ", "student"), SECTOR_EDUCATION),
    (("government", "ministry", "municipal", "police", "electoral"), SECTOR_PUBLIC),
    (("game", "gaming", "anime", "comic", "music", "movie", "stream", "video", "entertain", "media", "magazine", "news"), SECTOR_MEDIA),
    (("shop", "store", "retail", "commerce", "fashion", "market", "ticket", "hotel", "restaurant", "food"), SECTOR_RETAIL),
    (("hosting", "software", "tech", "cloud", "internet", "web", "app", "email", "forum", "social network", "telecom", "vpn", "domain"), SECTOR_TECH),
    (("energy", "utility", "transport", "airline", "logistics"), SECTOR_CRITICAL),
    (("manufactur", "automotive", "industrial"), SECTOR_INDUSTRY),
    (("consult", "legal", "recruit", "marketing"), SECTOR_PROFESSIONAL),
)

ATTACK_HACKING = "Hacking"
ATTACK_MALWARE = "Malware"
ATTACK_RANSOMWARE = "Ransomware"
ATTACK_SOCIAL = "Ingeniería social"
ATTACK_MISUSE = "Uso indebido"
ATTACK_ERROR = "Error"
ATTACK_PHYSICAL = "Físico"
ATTACK_DISRUPTION = "Disrupción"
ATTACK_DATA_THEFT = "Robo de datos"
ATTACK_HIJACKING = "Hijacking"
ATTACK_UNKNOWN = "Desconocido"

# VERIS actions are multi-valued; this precedence picks the primary one.
VCDB_ACTION_PRECEDENCE = (
    ("hacking", ATTACK_HACKING),
    ("malware", ATTACK_MALWARE),
    ("social", ATTACK_SOCIAL),
    ("misuse", ATTACK_MISUSE),
    ("error", ATTACK_ERROR),
    ("physical", ATTACK_PHYSICAL),
    ("environmental", ATTACK_UNKNOWN),
    ("unknown", ATTACK_UNKNOWN),
)

# Also multi-valued; ransomware wins when present, being the most specific.
EUREPOC_TYPE_PRECEDENCE = (
    ("Ransomware", ATTACK_RANSOMWARE),
    ("Disruption", ATTACK_DISRUPTION),
    ("Data theft", ATTACK_DATA_THEFT),
    ("Hijacking", ATTACK_HIJACKING),
)

# v3 thresholds applied to every record, whatever version scored it.
SEVERITY_BINS = (
    (0.0, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
)

CWE_UNKNOWN = "Unknown"
