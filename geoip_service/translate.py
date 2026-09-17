"""
Display helpers that turn saved GeoIP country/city values into human-readable
location strings without making network requests.
"""

from functools import lru_cache

from translation_service import get_cached_translation

from .normalize import convert_to_simplified, normalize_country_name


@lru_cache(maxsize=4096)
def translate_city_name(city_name: str) -> str:
    """Normalize a saved city value without making a network request."""
    source_text = str(city_name or "").strip()
    return convert_to_simplified(get_cached_translation(source_text, "city") or source_text)


def format_location_display(country_code: str, country_name: str, city_name: str) -> str:
    """
    Format location for display, avoiding duplicates like "香港 香港"
    Returns: "国家/地区 城市" or just "国家/地区" if city is same as country or empty
    """
    display_country = normalize_country_name(country_name, country_code)

    if not city_name:
        return display_country

    # Translate city name
    translated_city = translate_city_name(city_name)

    # Avoid duplicates: if city name is same as country/region name, just show country
    # e.g., "Hong Kong" city in "Hong Kong" -> just "China Hong Kong"
    # e.g., "Singapore" city in "Singapore" -> just "Singapore"
    if translated_city == country_name or translated_city in display_country:
        return display_country

    return f"{display_country} {translated_city}"
