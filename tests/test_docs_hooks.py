"""The documentation site's MkDocs hooks (.github/mkdocs_hooks.py): the Content-Security-Policy each page carries."""
import base64
import hashlib
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("mkdocs_hooks", Path(__file__).resolve().parent.parent / ".github/mkdocs_hooks.py")
hooks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hooks)


def _h(s):
    return "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"


def test_csp_meta_first_in_head_with_hashes_of_inline_scripts_and_styles():
    html = ('<html><head><meta charset="utf-8"><style>:root{--a:1}</style><script>var a=1</script>'
            '<script id="__config" type="application/json">{"x":1}</script><script src="b.js"></script>'
            '<script>var a=1</script></head><body></body></html>')
    out = hooks._csp(html)
    assert out.startswith('<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ')
    csp = out.split('content="', 1)[1].split('"', 1)[0]
    assert f"script-src 'self' {_h('var a=1')};" in csp                      # once; not the JSON, not the src
    assert _h('{"x":1}') not in csp
    assert f"style-src 'self' {_h(':root{--a:1}')};" in csp
    assert "'unsafe-inline'" not in csp and "object-src 'none'" in csp and "base-uri 'self'" in csp
