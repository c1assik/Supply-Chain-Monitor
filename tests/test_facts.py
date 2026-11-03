import ast

import pytest
from benchmarks.diff_pairs import build_pairs

from pypi_monitor.analyzers.facts import Fact, FactKind, extract_facts, may_have_facts


def facts(source: str) -> list[Fact]:
    return extract_facts(ast.parse(source))


def values(source: str, kind: FactKind) -> set[str]:
    return {fact.value for fact in facts(source) if fact.kind is kind}


def test_only_sensitive_imports_count() -> None:
    source = "import os, socket\nfrom urllib.request import urlopen\nfrom . import requests\n"
    assert values(source, FactKind.IMPORT) == {"socket", "urllib"}


def test_dynamic_import_is_an_import_and_a_call() -> None:
    source = '__import__("socket")\nimport importlib\nimportlib.import_module("subprocess")\n'
    assert values(source, FactKind.IMPORT) == {"socket", "subprocess"}
    assert values(source, FactKind.CALL) == {"__import__", "importlib.import_module"}


@pytest.mark.parametrize(
    ("source", "call"),
    [
        ("exec(x)", "exec"),
        ("import builtins\nbuiltins.eval(x)", "eval"),
        ("import os\nos.system(x)", "os.system"),
        ("import os as o\no.execv(x, y)", "os.execv"),
        ("from subprocess import Popen as P\nP(x)", "subprocess.Popen"),
        ("import subprocess as s\ns.run(x)", "subprocess.run"),
        ("from os import system\nsystem(x)", "os.system"),
        ("import requests\nrequests.post(x)", "requests.post"),
    ],
)
def test_calls_are_resolved_through_aliases(source: str, call: str) -> None:
    assert call in values(source, FactKind.CALL)


def test_lookalikes_are_not_dangerous_calls() -> None:
    source = "import re\nre.compile('x')\nself.exec()\nmodel.eval()\n"
    assert values(source, FactKind.CALL) == set()


@pytest.mark.parametrize(
    "source",
    [
        "import base64\nexec(base64.b64decode(x))",
        "from base64 import b64decode as d\nexec(d(x))",
        "import base64\nblob = base64.b64decode(x)\ncode = blob.decode()\nexec(code)",
        "import zlib\neval(compile(zlib.decompress(x), 'f', 'exec'))",
        "import requests\nexec(requests.get(u).text)",
        "import urllib.request\nexec(urllib.request.urlopen(u).read())",
    ],
)
def test_exec_of_decoded_data_is_found(source: str) -> None:
    assert values(source, FactKind.DECODED_EXEC)


def test_exec_of_plain_data_is_not_decoded() -> None:
    assert not values("exec(open('a').read())\nb = 1\n", FactKind.DECODED_EXEC)


def test_module_scope_is_told_from_functions() -> None:
    source = (
        "exec(a)\nclass C:\n    eval(b)\ndef f():\n    compile(c)\nlam = lambda: __import__('x')\n"
    )
    scope = {fact.value: fact.at_import for fact in facts(source)}
    assert scope == {"exec": True, "eval": True, "compile": False, "__import__": False}


def test_urls_are_compared_by_host() -> None:
    source = 'A = "https://evil.test/a"\nB = "https://evil.test:8080/b"\nC = b"http://x.test/"\n'
    assert values(source, FactKind.URL) == {"evil.test", "x.test"}


def test_documentation_hosts_are_not_targets() -> None:
    source = 'A = "http://www.w3.org/2000/svg"\nB = "https://docs.python.org/3/"\nC = "http://localhost:8000"\n'
    assert values(source, FactKind.URL) == set()


def test_ip_addresses() -> None:
    source = (
        'A = "http://203.0.113.7/c"\nB = "8.8.8.8"\nC = "8.8.4.4:53"\n'
        'D = "127.0.0.1"\nE = "192.168.1.1"\nF = "version 1.2.3.4 here"\nG = "999.1.1.1"\n'
    )
    assert values(source, FactKind.IP) == {"203.0.113.7", "8.8.8.8", "8.8.4.4"}
    assert values(source, FactKind.URL) == set()


def test_strings_that_only_look_like_urls() -> None:
    source = 'A = "must start with https://."\nB = "http://{host}/x"\nC = "https://a.example/"\n'
    assert values(source, FactKind.URL) == set()


def test_source_with_a_fact_is_never_skipped() -> None:
    for pair in build_pairs():
        for path, source in pair.new.items():
            if path.endswith(".py") and extract_facts(ast.parse(source)):
                assert may_have_facts(source.encode())


def test_plain_source_is_skipped() -> None:
    assert not may_have_facts(b"import json\n\n\ndef add(a, b):\n    return a + b\n")


@pytest.mark.parametrize(
    "source",
    [
        b"import SOCKET",
        b"from urllib.request import urlopen as u\nu(x)",
        b'A = "8.8.8.8"',
        b'A = "HTTP://evil.test"',
        b'__import__("x")',
    ],
)
def test_fact_words(source: bytes) -> None:
    assert may_have_facts(source)


@pytest.mark.parametrize(
    "source",
    [
        b"import os\nos.system(x)",
        b"import os as o\no.popen(x)",
        b"from os import execv as run\nrun(x)",
        b"from os import spawnl as run\nrun(x)",
        b"import ctypes as c\nc.CDLL(x)",
        b"import builtins as b\nb.exec(x)",
    ],
)
def test_every_dangerous_call_survives_the_cheap_test(source: bytes) -> None:
    assert may_have_facts(source)
    assert values(source.decode(), FactKind.CALL)


def test_a_function_called_on_import_runs_on_import() -> None:
    source = (
        "def _go():\n    exec(a)\ndef later():\n    eval(b)\n_go()\n"
        "if __name__ == '__main__':\n    compile(c)\n"
    )
    scope = {fact.value: fact.at_import for fact in facts(source)}
    assert scope == {"exec": True, "eval": False, "compile": False}
