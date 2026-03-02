import html
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Comment


DEFAULT_ALLOWED_TAGS = {
    'a',
    'abbr',
    'audio',
    'b',
    'blockquote',
    'br',
    'code',
    'dd',
    'div',
    'dl',
    'dt',
    'em',
    'h1',
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'hr',
    'i',
    'img',
    'li',
    'ol',
    'p',
    'pre',
    'span',
    'strong',
    'table',
    'tbody',
    'td',
    'tfoot',
    'th',
    'thead',
    'tr',
    'u',
    'ul',
    'video',
    'source',
    'canvas',
}

_COMMON_ALLOWED_ATTRS = {
    'class',
    'id',
    'title',
    'alt',
    'role',
    'width',
    'height',
    'colspan',
    'rowspan',
    'controls',
    'preload',
    'target',
    'rel',
    'hidden',
}

_TAG_ALLOWED_ATTRS = {
    'a': {'href'},
    'img': {'src'},
    'audio': {'src'},
    'video': {'src'},
    'source': {'src', 'type'},
    'iframe': {'src'},
    'td': {'style'},
    'div': {'style'},
    'span': {'style'},
    'h2': {'style'},
    'h3': {'style'},
    'h4': {'style'},
}

_BLOCKED_TAGS = {'script', 'style', 'object', 'embed'}
_DISALLOWED_STYLE_PATTERN = re.compile(r'(expression|url\s*\(|javascript:|@import)', re.IGNORECASE)
_DATA_MEDIA_PATTERN = re.compile(
    r'^data:(image|audio|video)/[a-z0-9.+-]+;base64,[a-z0-9+/=\s]+$',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TrustedHtml:
    html: str

    def __str__(self):
        return self.html


def trust_html(value):
    if isinstance(value, TrustedHtml):
        return value
    return TrustedHtml(str(value) if value is not None else '')


def escape_text(value):
    return html.escape(str(value) if value is not None else '', quote=True)


def escape_attr(value):
    escaped = html.escape(str(value) if value is not None else '', quote=True)
    return escaped.replace('`', '&#96;')


def sanitize_style(value):
    cleaned = str(value).strip() if value is not None else ''
    if not cleaned:
        return ''
    if _DISALLOWED_STYLE_PATTERN.search(cleaned):
        return ''
    return cleaned


def sanitize_url(value, allow_data_media=False):
    if value is None:
        return '#'

    raw = str(value).strip()
    if not raw:
        return '#'

    normalized = ''.join(ch for ch in raw if ch >= ' ' and ch != '\x7f')
    compact = re.sub(r'[\t\r\n\f\v ]+', '', normalized).lower()

    if compact.startswith('javascript:') or compact.startswith('vbscript:'):
        return '#'

    if compact.startswith('data:'):
        if allow_data_media and _DATA_MEDIA_PATTERN.match(normalized):
            return normalized
        return '#'

    split = urlsplit(normalized)
    scheme = split.scheme.lower()
    if scheme in ('', 'http', 'https', 'mailto', 'tel', 'ftp', 'file'):
        return normalized
    return '#'


def sanitize_html_fragment(value, allowed_tags=None):
    if value is None:
        return ''

    allowed = set(allowed_tags) if allowed_tags else set(DEFAULT_ALLOWED_TAGS)
    allowed = {tag.lower() for tag in allowed}

    soup = BeautifulSoup(str(value), 'html.parser')

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    for tag in soup.find_all(True):
        name = tag.name.lower()
        if name in _BLOCKED_TAGS:
            tag.decompose()
            continue

        if name not in allowed:
            tag.unwrap()
            continue

        allowed_attrs = set(_COMMON_ALLOWED_ATTRS)
        allowed_attrs.update(_TAG_ALLOWED_ATTRS.get(name, set()))

        new_attrs = {}
        for attr, raw_attr_value in list(tag.attrs.items()):
            attr_name = attr.lower()
            if attr_name.startswith('on'):
                continue
            if attr_name not in allowed_attrs:
                continue

            attr_value = ' '.join(raw_attr_value) if isinstance(raw_attr_value, list) else str(raw_attr_value)

            if attr_name in ('href', 'src'):
                allow_data = attr_name == 'src' and name in ('img', 'audio', 'video', 'source')
                new_attrs[attr_name] = sanitize_url(attr_value, allow_data_media=allow_data)
            elif attr_name == 'style':
                clean_style = sanitize_style(attr_value)
                if clean_style:
                    new_attrs[attr_name] = clean_style
            else:
                new_attrs[attr_name] = attr_value

        tag.attrs = new_attrs

    return ''.join(str(item) for item in soup.contents)
