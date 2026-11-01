"""What a Python module can do, read from its AST: the facts a version diff compares."""

import ast
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


class FactKind(StrEnum):
    IMPORT = "import"
    CALL = "call"
    URL = "url"
    IP = "ip"
    DECODED_EXEC = "decoded_exec"


@dataclass(frozen=True)
class Fact:
    kind: FactKind
    value: str
    line: int
    # Runs when the module is imported, not when somebody calls a function.
    at_import: bool

    @property
    def key(self) -> tuple[FactKind, str]:
        """Identity of a fact in a diff: its place in the file does not matter."""
        return self.kind, self.value


SENSITIVE_MODULES = frozenset(
    {
        "aiohttp",
        "base64",
        "binascii",
        "browser_cookie3",
        "ctypes",
        "dns",
        "ftplib",
        "getpass",
        "http",
        "httpx",
        "keyring",
        "marshal",
        "paramiko",
        "pickle",
        "pty",
        "pyperclip",
        "requests",
        "runpy",
        "smtplib",
        "socket",
        "subprocess",
        "telnetlib",
        "urllib",
        "urllib2",
        "urllib3",
        "websocket",
        "websockets",
        "win32crypt",
        "winreg",
    }
)
_DYNAMIC_IMPORTS = frozenset({"__import__", "importlib.import_module"})
_EXECUTORS = frozenset({"exec", "eval", "compile"})
_DANGEROUS_CALLS = (
    _EXECUTORS
    | _DYNAMIC_IMPORTS
    | frozenset(
        {
            "ctypes.CDLL",
            "httpx.get",
            "httpx.post",
            "requests.get",
            "requests.post",
            "socket.create_connection",
            "socket.socket",
            "urllib.request.urlopen",
            "urllib2.urlopen",
            "ctypes.WinDLL",
            "ctypes.cdll.LoadLibrary",
            "ctypes.windll.LoadLibrary",
            "marshal.loads",
            "os.popen",
            "os.startfile",
            "os.system",
            "pickle.loads",
            "pty.spawn",
            "runpy.run_module",
            "runpy.run_path",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "subprocess.run",
        }
    )
)
_DANGEROUS_PREFIXES = ("os.exec", "os.posix_spawn", "os.spawn")
# What turns an opaque blob or a remote answer into code for exec().
_DECODERS = frozenset(
    {
        "base64.a85decode",
        "base64.b16decode",
        "base64.b32decode",
        "base64.b64decode",
        "base64.b85decode",
        "base64.decodebytes",
        "base64.urlsafe_b64decode",
        "binascii.a2b_base64",
        "binascii.a2b_hex",
        "binascii.unhexlify",
        "bytes.fromhex",
        "bz2.decompress",
        "codecs.decode",
        "gzip.decompress",
        "lzma.decompress",
        "marshal.loads",
        "zlib.decompress",
        "httpx.get",
        "requests.get",
        "requests.post",
        "urllib.request.urlopen",
        "urllib2.urlopen",
    }
)
_BUILTIN_PREFIXES = ("builtins.", "__builtins__.")
# Every fact has one of these in the source text: a call or an import is written by name, and an
# alias still names its module in the import. Built from the lists above so as not to drift apart.
_FACT_NAMES = (
    SENSITIVE_MODULES
    | {name.split(".")[0] for name in _DANGEROUS_CALLS | set(_DANGEROUS_PREFIXES)}
    | {name.split(".")[-1] for name in _DANGEROUS_CALLS}
)
_FACT_WORDS = re.compile(
    rb"https?:|\d\.\d+\.\d+\.\d|\b(?:" + "|".join(sorted(_FACT_NAMES)).encode() + rb")\b",
    re.IGNORECASE,
)
_HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s'\"<>\\]+", re.IGNORECASE)
_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?")
# Not `is_global`: it also rejects documentation ranges, and a payload is free to use those.
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
        "::/127",
        "fc00::/7",
        "fe80::/10",
    )
)
_MAX_SCANNED_STRING = 1024 * 1024
# Mentioned all the time in schemas, comments turned strings and examples.
_HARMLESS_HOSTS = frozenset({"localhost", "www.w3.org", "w3.org", "schemas.xmlsoap.org"})
_HARMLESS_DOMAINS = (
    ".example",
    ".example.com",
    ".example.org",
    ".invalid",
    ".local",
    ".localhost",
    ".pypi.org",
    ".python.org",
    ".readthedocs.io",
)
_HARMLESS_EXACT_DOMAINS = frozenset({"example.com", "example.org", "python.org", "pypi.org"})


def may_have_facts(source: bytes) -> bool:
    """False when a source certainly has no facts: a cheap test that spares parsing it."""
    return _FACT_WORDS.search(source) is not None


def extract_facts(tree: ast.Module) -> list[Fact]:
    return _Visitor(tree).run()


class _Visitor(ast.NodeVisitor):
    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._aliases = _aliases(tree)
        self._tainted: set[str] | None = None
        self._function_depth = 0
        self._facts: list[Fact] = []

    def run(self) -> list[Fact]:
        self.visit(self._tree)
        return self._facts

    def _collect_tainted(self) -> set[str]:
        """Names holding decoded data, for `code = b64decode(blob); exec(code)`."""
        tainted: set[str] = set()
        assignments = [node for node in ast.walk(self._tree) if isinstance(node, ast.Assign)]
        # Each pass follows one more step of `a = decode(x); b = a.decode(); exec(b)`.
        for _ in range(3):
            for node in assignments:
                if self._decoder_in(node.value, tainted) is not None:
                    tainted.update(t.id for t in node.targets if isinstance(t, ast.Name))
        return tainted

    def _add(self, kind: FactKind, value: str, node: ast.expr | ast.stmt) -> None:
        self._facts.append(Fact(kind, value, node.lineno, self._function_depth == 0))

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function
    visit_Lambda = _visit_function

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._add_import(alias.name, node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.level and node.module:
            self._add_import(node.module, node)

    def _add_import(self, module: str, node: ast.stmt | ast.expr) -> None:
        root = module.partition(".")[0]
        if root in SENSITIVE_MODULES:
            self._add(FactKind.IMPORT, root, node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if name is not None:
            if name in _DYNAMIC_IMPORTS and _first_string(node) is not None:
                self._add_import(_first_string(node) or "", node)
            if name in _DANGEROUS_CALLS or name.startswith(_DANGEROUS_PREFIXES):
                self._add(FactKind.CALL, name, node)
            if name in _EXECUTORS:
                # Most modules have no executor at all, so the walk over assignments waits for one.
                if self._tainted is None:
                    self._tainted = self._collect_tainted()
                tainted = self._tainted
                source = next(
                    (found for arg in node.args if (found := self._decoder_in(arg, tainted))), None
                )
                if source is not None:
                    self._add(FactKind.DECODED_EXEC, f"{name}({source})", node)
        self.generic_visit(node)

    def _decoder_in(self, expression: ast.expr, tainted: set[str]) -> str | None:
        for node in ast.walk(expression):
            if isinstance(node, ast.Name) and node.id in tainted:
                return node.id
            if isinstance(node, ast.Call):
                name = self._call_name(node)
                if name in _DECODERS:
                    return name
        return None

    def _call_name(self, node: ast.Call) -> str | None:
        """Dotted name of a call with import aliases resolved: `P` for `subprocess.Popen`."""
        parts: list[str] = []
        function = node.func
        while isinstance(function, ast.Attribute):
            parts.append(function.attr)
            function = function.value
        if not isinstance(function, ast.Name):
            return None
        parts.append(self._aliases.get(function.id, function.id))
        name = ".".join(reversed(parts))
        for prefix in _BUILTIN_PREFIXES:
            name = name.removeprefix(prefix)
        return name

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if not isinstance(value, str) or len(value) > _MAX_SCANNED_STRING:
            return
        for kind, found in _network_targets(value):
            self._add(kind, found, node)


def _aliases(tree: ast.Module) -> dict[str, str]:
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _first_string(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant):
        value = node.args[0].value
        return value if isinstance(value, str) else None
    return None


def _network_targets(text: str) -> list[tuple[FactKind, str]]:
    found = []
    # A bare address only counts when it is the whole string: "1.2.3.4" inside text is a version.
    bare = _IP.fullmatch(text.strip())
    if bare and _is_remote_ip(bare[1]):
        found.append((FactKind.IP, bare[1]))
    for url in _URL.findall(text):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if not host or not _HOST.fullmatch(host):
            continue
        if _is_remote_ip(host):
            found.append((FactKind.IP, host))
        elif not _is_harmless_host(host) and not _IP.fullmatch(host):
            found.append((FactKind.URL, host))
    return found


def _is_remote_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not any(
        address in network for network in _LOCAL_NETWORKS if network.version == address.version
    )


def _is_harmless_host(host: str) -> bool:
    return (
        host in _HARMLESS_HOSTS
        or host in _HARMLESS_EXACT_DOMAINS
        or host.endswith(_HARMLESS_DOMAINS)
    )
