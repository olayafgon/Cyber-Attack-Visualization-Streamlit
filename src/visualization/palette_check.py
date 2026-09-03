"""Verifies the perceptual separation of the project palette.

Checks every categorical palette against four gates: the lightness band its
swatches span, the chroma floor, the minimum CIEDE2000 distance between any
pair of swatches under normal vision and under the three dichromacies, and
the contrast ratio of each swatch against its own surface.

Usage:
    python -m src.visualization.palette_check
"""

from __future__ import annotations

import itertools

import numpy as np

from src.visualization import theme

# Viénot, Brettel and Mollon (1999) dichromacy simulation in LMS space.
_RGB_TO_LMS = np.array(
    [[17.8824, 43.5161, 4.11935],
     [3.45565, 27.1554, 3.86714],
     [0.0299566, 0.184309, 1.46709]]
)
_DICHROMAT_MATRICES = {
    "protanopía": np.array([[0, 2.02344, -2.52581], [0, 1, 0], [0, 0, 1]]),
    "deuteranopía": np.array([[1, 0, 0], [0.494207, 0, 1.24827], [0, 0, 1]]),
    "tritanopía": np.array([[1, 0, 0], [0, 1, 0], [-0.395913, 0.801109, 0]]),
}


def _to_linear(rgb: np.ndarray) -> np.ndarray:
    """Removes the sRGB transfer function."""
    return np.where(rgb <= 0.04045, rgb / 12.92, ((rgb + 0.055) / 1.055) ** 2.4)


def _to_srgb(linear: np.ndarray) -> np.ndarray:
    """Applies the sRGB transfer function."""
    clipped = np.clip(linear, 0.0, 1.0)
    return np.where(clipped <= 0.0031308, clipped * 12.92, 1.055 * clipped ** (1 / 2.4) - 0.055)


def hex_to_rgb(color: str) -> np.ndarray:
    """Converts a hex color to a float RGB triplet in [0, 1]."""
    value = color.lstrip("#")
    return np.array([int(value[i:i + 2], 16) for i in (0, 2, 4)]) / 255.0


def to_lab(color: str) -> np.ndarray:
    """Converts a hex color to CIE L*a*b* under the D65 illuminant."""
    matrix = np.array(
        [[0.4124564, 0.3575761, 0.1804375],
         [0.2126729, 0.7151522, 0.0721750],
         [0.0193339, 0.1191920, 0.9503041]]
    )
    xyz = matrix @ _to_linear(hex_to_rgb(color)) / np.array([0.95047, 1.0, 1.08883])
    f = np.where(xyz > 0.008856, np.cbrt(xyz), 7.787 * xyz + 16 / 116)
    return np.array([116 * f[1] - 16, 500 * (f[0] - f[1]), 200 * (f[1] - f[2])])


def simulate(color: str, deficiency: str) -> str:
    """Returns the hex color as seen under the given dichromacy."""
    lms = _RGB_TO_LMS @ _to_linear(hex_to_rgb(color))
    simulated = np.linalg.solve(_RGB_TO_LMS, _DICHROMAT_MATRICES[deficiency] @ lms)
    return "#" + "".join(f"{int(round(c * 255)):02x}" for c in _to_srgb(simulated))


def delta_e_2000(first: str, second: str) -> float:
    """Computes the CIEDE2000 difference between two hex colors."""
    lab1, lab2 = to_lab(first), to_lab(second)
    l1, a1, b1 = lab1
    l2, a2, b2 = lab2
    avg_l = (l1 + l2) / 2
    c1, c2 = np.hypot(a1, b1), np.hypot(a2, b2)
    avg_c = (c1 + c2) / 2
    g = 0.5 * (1 - np.sqrt(avg_c ** 7 / (avg_c ** 7 + 25.0 ** 7))) if avg_c > 0 else 0.0
    a1p, a2p = a1 * (1 + g), a2 * (1 + g)
    c1p, c2p = np.hypot(a1p, b1), np.hypot(a2p, b2)
    avg_cp = (c1p + c2p) / 2
    h1p = np.degrees(np.arctan2(b1, a1p)) % 360
    h2p = np.degrees(np.arctan2(b2, a2p)) % 360
    delta_lp = l2 - l1
    delta_cp = c2p - c1p
    if c1p * c2p == 0:
        delta_hp = 0.0
    elif abs(h2p - h1p) <= 180:
        delta_hp = h2p - h1p
    else:
        delta_hp = h2p - h1p - 360 * np.sign(h2p - h1p)
    delta_hp_big = 2 * np.sqrt(c1p * c2p) * np.sin(np.radians(delta_hp) / 2)
    if c1p * c2p == 0:
        avg_hp = h1p + h2p
    elif abs(h1p - h2p) <= 180:
        avg_hp = (h1p + h2p) / 2
    elif h1p + h2p < 360:
        avg_hp = (h1p + h2p + 360) / 2
    else:
        avg_hp = (h1p + h2p - 360) / 2
    t = (
        1
        - 0.17 * np.cos(np.radians(avg_hp - 30))
        + 0.24 * np.cos(np.radians(2 * avg_hp))
        + 0.32 * np.cos(np.radians(3 * avg_hp + 6))
        - 0.20 * np.cos(np.radians(4 * avg_hp - 63))
    )
    s_l = 1 + (0.015 * (avg_l - 50) ** 2) / np.sqrt(20 + (avg_l - 50) ** 2)
    s_c = 1 + 0.045 * avg_cp
    s_h = 1 + 0.015 * avg_cp * t
    r_t = (
        -2
        * np.sqrt(avg_cp ** 7 / (avg_cp ** 7 + 25.0 ** 7))
        * np.sin(np.radians(60 * np.exp(-(((avg_hp - 275) / 25) ** 2))))
    )
    return float(
        np.sqrt(
            (delta_lp / s_l) ** 2
            + (delta_cp / s_c) ** 2
            + (delta_hp_big / s_h) ** 2
            + r_t * (delta_cp / s_c) * (delta_hp_big / s_h)
        )
    )


def contrast_ratio(color: str, background: str) -> float:
    """Computes the WCAG contrast ratio between a color and its background."""
    weights = np.array([0.2126, 0.7152, 0.0722])
    lum = [float(weights @ _to_linear(hex_to_rgb(c))) for c in (color, background)]
    return (max(lum) + 0.05) / (min(lum) + 0.05)


def report(name: str, palette: list[str], background: str) -> dict[str, float]:
    """Measures one palette on its own surface and prints the result."""
    lightness = [to_lab(c)[0] for c in palette]
    chroma = [float(np.hypot(*to_lab(c)[1:])) for c in palette]
    pairs = list(itertools.combinations(palette, 2))
    metrics = {
        "banda de luminosidad L*": max(lightness) - min(lightness),
        "croma mínimo C*": min(chroma),
        "ΔE00 mínimo, visión normal": min(delta_e_2000(a, b) for a, b in pairs),
        "contraste mínimo con el fondo": min(contrast_ratio(c, background) for c in palette),
    }
    for deficiency in _DICHROMAT_MATRICES:
        metrics[f"ΔE00 mínimo, {deficiency}"] = min(
            delta_e_2000(simulate(a, deficiency), simulate(b, deficiency)) for a, b in pairs
        )
    print(f"\n{name} ({len(palette)} casillas, fondo {background})")
    for label, value in metrics.items():
        print(f"  {label:<32} {value:6.2f}")
    return metrics


def report_no_data(variant: str, ramp: list[str], no_data: str, background: str) -> dict[str, float]:
    """Checks that the missing-data neutral sits outside the ramp it borders.

    Args:
        variant: Theme variant name, for the printed heading.
        ramp: The activity ramp swatches of that variant.
        no_data: The neutral used for undocumented cells and countries.
        background: The surface both are drawn on.

    Returns:
        The measured lightness figures.
    """
    band = [to_lab(c)[0] for c in ramp]
    low, high = min(band), max(band)
    neutral = to_lab(no_data)[0]
    position = "por debajo" if neutral < low else "por encima" if neutral > high else "DENTRO"
    metrics = {
        "L* del extremo bajo de la rampa": low,
        "L* del extremo alto de la rampa": high,
        "L* del gris de «sin datos»": neutral,
        "margen fuera de la banda": min(abs(neutral - low), abs(neutral - high)),
        "contraste del gris con el fondo": contrast_ratio(no_data, background),
    }
    print(f"\nAusencia de dato, variante {variant} (fondo {background})")
    for label, value in metrics.items():
        print(f"  {label:<34} {value:6.2f}")
    print(f"  {'posición respecto a la rampa':<34} {position:>6}")
    return metrics


OKABE_ITO = ["#0072b2", "#e69f00", "#009e73", "#cc79a7", "#d55e00", "#56b4e9"]


def main() -> int:
    """Reports every categorical palette of the project."""
    report("Referencia Okabe-Ito", OKABE_ITO, "#ffffff")
    report("Paleta cualitativa, variante clara", theme._CATEGORICAL_LIGHT, "#ffffff")
    report("Paleta cualitativa, variante oscura", theme._CATEGORICAL_DARK, theme.DARK_BACKGROUND)
    report("Bandas de severidad, variante clara", theme._SEVERITY_LIGHT, "#ffffff")
    report("Bandas de severidad, variante oscura", theme._SEVERITY_DARK, theme.DARK_BACKGROUND)
    report(
        "Acentos de explotación, variante clara",
        [theme._KEV_LIGHT[0], theme._KEV_LIGHT[1], theme.NEUTRAL_GRAY],
        "#ffffff",
    )
    report(
        "Acentos de explotación, variante oscura",
        [theme._KEV_DARK[0], theme._KEV_DARK[1], theme.NEUTRAL_GRAY],
        theme.DARK_BACKGROUND,
    )
    report_no_data("clara", theme._ACTIVITY_RANGE_LIGHT, theme._NO_DATA_LIGHT, "#ffffff")
    report_no_data("oscura", theme._ACTIVITY_RANGE_DARK, theme._NO_DATA_DARK, theme.DARK_BACKGROUND)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
