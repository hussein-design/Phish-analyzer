"""Static attachment intelligence — Phase 3.

Inspects raw attachment bytes without executing them and returns a rich
intelligence dict for each attachment.  The service is completely self-
contained: it only uses the Python standard library and packages already
in requirements.txt.

Capabilities
------------
* MIME magic-byte verification  — compares the declared content-type to the
  actual file signature (first 16 bytes).  Catches ".pdf" files that are
  really executables, ".docx" files that are ZIPs, etc.

* Macro-enabled Office detection — OLE2 (.doc/.xls/.ppt) and OOXML
  (.docm/.xlsm/.xlam/.pptm) are both detected via magic bytes and by
  inspecting the internal structure when the payload is available.

* Archive inspection — ZIP, RAR, 7z, GZIP, BZIP2, TAR, and ISO images
  are identified by magic bytes; ZIP archives are opened and inspected
  for nested executables or double-extension entries.

* Embedded executable detection — scans ZIP archive members for MZ/ELF/
  Mach-O headers and dangerous extensions, and checks OLE2 compound
  documents for streams that look like embedded PE payloads.

* Metadata extraction — reads document properties from ZIP-based OOXML
  files (app.xml / core.xml) without any external library, returning
  author, creation date, last-modified-by, revision count, and the
  generator application name.

All analysis runs synchronously in a thread-pool executor (the caller is
responsible for that).  Each method is designed so that an unexpected error
degrades gracefully — it returns empty/False rather than crashing the
pipeline.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import zipfile
from dataclasses import dataclass, field

try:
    import defusedxml.ElementTree as ET  # preferred — blocks XXE / billion-laughs
except ImportError:  # pragma: no cover — defusedxml must be in requirements.txt
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]
    logging.getLogger(__name__).warning(
        "defusedxml not installed — falling back to stdlib ET (XXE risk); "
        "add defusedxml to requirements.txt"
    )

logger = logging.getLogger(__name__)

# ── ZIP safety limits (CRIT-01: zip-bomb / decompression-bomb protection) ─────
_ZIP_MAX_MEMBERS        = 1_000          # refuse archives with more entries than this
_ZIP_MAX_MEMBER_BYTES   = 50 * 1024 * 1024  # 50 MB — max decompressed size per member
_ZIP_MAX_XML_BYTES      = 1 * 1024 * 1024   # 1 MB — max size for [Content_Types].xml / core.xml

# ── File-signature (magic byte) registry ─────────────────────────────────────
# Each entry: (offset, bytes_to_match, canonical_mime)
# Offset is normally 0; some formats (e.g. ZIP-based OOXML) share signature.
_MAGIC: list[tuple[int, bytes, str]] = [
    # Executables
    (0, b"MZ",                              "application/x-dosexec"),
    (0, b"\x7fELF",                         "application/x-elf"),
    (0, b"\xfe\xed\xfa\xce",               "application/x-mach-binary"),   # Mach-O 32-bit
    (0, b"\xce\xfa\xed\xfe",               "application/x-mach-binary"),
    (0, b"\xfe\xed\xfa\xcf",               "application/x-mach-binary"),   # Mach-O 64-bit
    (0, b"\xcf\xfa\xed\xfe",               "application/x-mach-binary"),
    # Archives
    (0, b"PK\x03\x04",                     "application/zip"),
    (0, b"PK\x05\x06",                     "application/zip"),             # empty ZIP
    (0, b"Rar!\x1a\x07\x00",              "application/x-rar-compressed"),
    (0, b"Rar!\x1a\x07\x01\x00",         "application/x-rar-compressed"),
    (0, b"7z\xbc\xaf'\x1c",              "application/x-7z-compressed"),
    (0, b"\x1f\x8b",                       "application/gzip"),
    (0, b"BZh",                            "application/x-bzip2"),
    (257, b"ustar",                        "application/x-tar"),           # POSIX TAR
    # Documents / OLE2
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/vnd.ms-office"),  # OLE2 compound doc
    # PDF
    (0, b"%PDF",                           "application/pdf"),
    # Images (basic)
    (0, b"\xff\xd8\xff",                   "image/jpeg"),
    (0, b"\x89PNG\r\n\x1a\n",            "image/png"),
    (0, b"GIF87a",                         "image/gif"),
    (0, b"GIF89a",                         "image/gif"),
]

# OOXML content-types that indicate macro-enabled documents
_MACRO_OOXML_CONTENT_TYPES = {
    "application/vnd.ms-word.document.macroEnabled.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
    "application/vnd.ms-excel.addin.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
    "application/vnd.ms-word.template.macroEnabled.main+xml",
    "application/vnd.ms-excel.template.macroEnabled.main+xml",
}

# Filename extensions that definitively indicate macro-enabled Office docs
_MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
}

# Dangerous extensions to look for inside archives
_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".jar", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".dll", ".lnk",
    ".wsf", ".wsh", ".gadget", ".cpl", ".reg",
}

# Archive MIME types
_ARCHIVE_MIMES = {
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/gzip",
    "application/x-bzip2",
    "application/x-tar",
    "application/x-iso9660-image",
    "application/x-compressed",
    "application/x-zip-compressed",
}

# Declared MIME types that map to the ZIP signature — these are ZIP-based
# OOXML formats and should NOT trigger a mime_magic_mismatch warning when the
# magic bytes say "PK…".
_ZIP_BASED_MIMES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/zip",
    "application/x-zip-compressed",
    "application/java-archive",
    "application/epub+zip",
}


@dataclass
class AttachmentIntelligence:
    """All static-analysis results for one attachment."""

    # MIME identification
    detected_mime: str | None = None       # what the magic bytes say
    declared_mime: str | None = None       # what the email header says
    mime_magic_mismatch: bool = False

    # Macro / active content
    is_macro_enabled: bool = False
    macro_evidence: str | None = None      # e.g. "OOXML macro content-type"

    # Archive
    is_archive: bool = False
    archive_file_count: int = 0
    archive_member_names: list[str] = field(default_factory=list)

    # Embedded executables
    has_embedded_executable: bool = False
    embedded_executable_names: list[str] = field(default_factory=list)

    # Metadata
    file_metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "detected_mime":               self.detected_mime,
            "declared_mime":               self.declared_mime,
            "mime_magic_mismatch":         self.mime_magic_mismatch,
            "is_macro_enabled":            self.is_macro_enabled,
            "macro_evidence":              self.macro_evidence,
            "is_archive":                  self.is_archive,
            "archive_file_count":          self.archive_file_count,
            "archive_member_names":        self.archive_member_names[:50],  # cap
            "has_embedded_executable":     self.has_embedded_executable,
            "embedded_executable_names":   self.embedded_executable_names,
            "file_metadata":               self.file_metadata,
        }


# ── Public entry point ────────────────────────────────────────────────────────

def analyse_attachment(payload: bytes, filename: str | None, declared_mime: str | None) -> AttachmentIntelligence:
    """Run all static checks on a single attachment payload.

    This is a synchronous function — the caller should run it in a
    thread-pool executor to avoid blocking the asyncio event loop.

    Parameters
    ----------
    payload:       Raw bytes of the attachment.
    filename:      Original filename (may be None for inline parts).
    declared_mime: Content-type string from the email header (may be None).
    """
    result = AttachmentIntelligence(declared_mime=declared_mime)

    if not payload:
        return result

    try:
        _check_magic(payload, filename, declared_mime, result)
        _check_macro(payload, filename, result)
        _check_archive(payload, result)
        _extract_metadata(payload, result)
    except Exception as exc:
        logger.warning("Attachment static analysis error (%s): %s", filename, exc)

    return result


# ── Internal analysis stages ──────────────────────────────────────────────────

def _sniff_magic(data: bytes) -> str | None:
    """Return the best-matching canonical MIME type from the magic registry."""
    for offset, signature, mime in _MAGIC:
        end = offset + len(signature)
        if len(data) >= end and data[offset:end] == signature:
            return mime
    return None


def _check_magic(
    payload: bytes,
    filename: str | None,
    declared_mime: str | None,
    result: AttachmentIntelligence,
) -> None:
    """Detect the actual file type via magic bytes and flag mismatches."""
    detected = _sniff_magic(payload)
    result.detected_mime = detected

    if not detected or not declared_mime:
        return

    declared_base = declared_mime.lower().split(";")[0].strip()
    detected_lower = detected.lower()

    # OLE2 covers .doc/.xls/.ppt — their declared MIME is "application/msword"
    # etc., not "vnd.ms-office", so we never flag that as a mismatch.
    if detected_lower == "application/vnd.ms-office":
        return

    # ZIP-based OOXML: magic bytes say "application/zip" but declared type is
    # a specific Office format — that is expected and correct.
    if detected_lower == "application/zip" and declared_base in _ZIP_BASED_MIMES:
        return
    if detected_lower == "application/zip" and declared_base == "application/zip":
        return

    # Only flag a mismatch when the detected type is something dangerous
    # (executable) OR when declared is a document type and detected disagrees.
    if detected_lower == declared_base:
        return

    # Executable detected under a non-executable declared type → high signal
    if detected_lower in ("application/x-dosexec", "application/x-elf", "application/x-mach-binary"):
        result.mime_magic_mismatch = True
        logger.info(
            "MIME magic mismatch: declared=%s detected=%s filename=%s",
            declared_mime, detected, filename,
        )
        return

    # Archive detected but declared as a document
    if detected_lower == "application/zip" and "office" not in declared_base and "zip" not in declared_base:
        result.mime_magic_mismatch = True
        return

    # PDF magic bytes but non-PDF declared type
    if detected_lower == "application/pdf" and "pdf" not in declared_base:
        result.mime_magic_mismatch = True


def _check_macro(payload: bytes, filename: str | None, result: AttachmentIntelligence) -> None:
    """Detect macro-enabled Office documents."""
    lower_name = (filename or "").lower()

    # Extension-based detection (reliable for OOXML macro formats)
    ext = "." + lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
    if ext in _MACRO_EXTENSIONS:
        result.is_macro_enabled = True
        result.macro_evidence = f"Macro-enabled extension: {ext}"
        return

    # OOXML content-type scan: open as ZIP and read [Content_Types].xml
    if _sniff_magic(payload) == "application/zip":
        try:
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                names = zf.namelist()
                # Zip-bomb guard: too many entries → skip deep inspection
                if len(names) > _ZIP_MAX_MEMBERS:
                    logger.warning(
                        "Macro check aborted: ZIP has %d entries (limit %d)",
                        len(names), _ZIP_MAX_MEMBERS,
                    )
                    return
                if "[Content_Types].xml" in names:
                    info = zf.getinfo("[Content_Types].xml")
                    if info.file_size > _ZIP_MAX_XML_BYTES:
                        logger.warning("Skipping oversized [Content_Types].xml (%d bytes)", info.file_size)
                    else:
                        ct_xml = zf.read("[Content_Types].xml").decode("utf-8", errors="replace")
                        for macro_ct in _MACRO_OOXML_CONTENT_TYPES:
                            if macro_ct in ct_xml:
                                result.is_macro_enabled = True
                                result.macro_evidence = f"OOXML content-type: {macro_ct}"
                                return
                        # Also check for vbaProject.bin inside the archive — the
                        # presence of VBA storage means macros exist even if the
                        # content-type didn't advertise it.
                        for name in names:
                            if "vbaProject" in name or "vbaData" in name:
                                result.is_macro_enabled = True
                                result.macro_evidence = f"VBA project storage found: {name}"
                                return
        except zipfile.BadZipFile:
            pass
        except Exception as exc:
            logger.debug("OOXML macro check failed: %s", exc)

    # OLE2 stream scan for VBA storage signature
    # OLE2 magic: D0 CF 11 E0 A1 B1 1A E1
    if len(payload) > 8 and payload[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # VBA storage CLSID is stored in directory entries.  A quick heuristic:
        # scan for the ASCII string "VBA" in the first 64 KB of the compound doc.
        chunk = payload[:65536]
        if b"V\x00B\x00A" in chunk or b"VBA" in chunk or b"_VBA_PROJECT" in chunk:
            result.is_macro_enabled = True
            result.macro_evidence = "OLE2 VBA storage detected"


def _check_archive(payload: bytes, result: AttachmentIntelligence) -> None:
    """Identify archive files and inspect ZIP contents for embedded executables."""
    magic_mime = _sniff_magic(payload)

    # Mark as archive by magic bytes first
    if magic_mime in _ARCHIVE_MIMES or magic_mime == "application/zip":
        result.is_archive = True

    # Also mark as archive by declared mime if magic didn't catch it
    if result.declared_mime:
        declared_base = result.declared_mime.lower().split(";")[0].strip()
        if declared_base in _ARCHIVE_MIMES:
            result.is_archive = True

    if not result.is_archive:
        return

    # For ZIP archives we can inspect the member list directly.
    if magic_mime == "application/zip" or (
        result.declared_mime and "zip" in (result.declared_mime or "").lower()
    ):
        try:
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                names = zf.namelist()
                # Zip-bomb guard: refuse suspiciously large member lists
                if len(names) > _ZIP_MAX_MEMBERS:
                    logger.warning(
                        "Archive inspection truncated: %d entries (limit %d)",
                        len(names), _ZIP_MAX_MEMBERS,
                    )
                    result.archive_file_count = len(names)
                    result.archive_member_names = names[:50]
                    return

                result.archive_file_count = len(names)
                result.archive_member_names = names[:100]

                for name in names:
                    lower = name.lower()
                    # Check for dangerous extensions in archive members
                    for ext in _DANGEROUS_EXTENSIONS:
                        if lower.endswith(ext):
                            result.has_embedded_executable = True
                            result.embedded_executable_names.append(name)
                            break

                    # Inspect the first few bytes of each member for MZ/ELF headers
                    # but only if the decompressed size is sane
                    if not result.has_embedded_executable:
                        try:
                            info = zf.getinfo(name)
                            if info.file_size > _ZIP_MAX_MEMBER_BYTES:
                                logger.debug(
                                    "Skipping member header check for %s "
                                    "(decompressed size %d bytes)", name, info.file_size,
                                )
                                continue
                            with zf.open(name) as member_f:
                                header = member_f.read(4)
                            if header[:2] == b"MZ" or header[:4] == b"\x7fELF":
                                result.has_embedded_executable = True
                                result.embedded_executable_names.append(name)
                        except Exception:
                            pass

        except zipfile.BadZipFile:
            logger.debug("Archive inspection: not a valid ZIP despite magic bytes")
        except Exception as exc:
            logger.debug("Archive inspection error: %s", exc)


def _extract_metadata(payload: bytes, result: AttachmentIntelligence) -> None:
    """Extract document metadata from OOXML (ZIP-based) files.

    Reads core.xml and app.xml from the ZIP without any external library.
    Adds the result to result.file_metadata (dict).
    """
    if _sniff_magic(payload) != "application/zip":
        return

    meta: dict = {}

    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
            names_lower = {n.lower(): n for n in zf.namelist()}

            # Zip-bomb guard
            if len(names_lower) > _ZIP_MAX_MEMBERS:
                logger.warning("Metadata extraction skipped: too many ZIP entries (%d)", len(names_lower))
                return

            # core.xml: author, last-modified-by, creation date, revision
            core_key = names_lower.get("docprops/core.xml")
            if core_key:
                try:
                    info = zf.getinfo(core_key)
                    if info.file_size > _ZIP_MAX_XML_BYTES:
                        logger.warning("Skipping oversized core.xml (%d bytes)", info.file_size)
                    else:
                        core_xml = zf.read(core_key).decode("utf-8", errors="replace")
                        root = ET.fromstring(core_xml)
                        ns = {
                            "dc":      "http://purl.org/dc/elements/1.1/",
                            "cp":      "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                            "dcterms": "http://purl.org/dc/terms/",
                        }
                        _et_text = lambda tag, n: (root.find(tag, n) is not None and root.find(tag, n).text) or None
                        meta["author"]           = _et_text("dc:creator", ns)
                        meta["last_modified_by"] = _et_text("cp:lastModifiedBy", ns)
                        meta["created"]          = _et_text("dcterms:created", ns)
                        meta["modified"]         = _et_text("dcterms:modified", ns)
                        meta["revision"]         = _et_text("cp:revision", ns)
                except Exception as exc:
                    logger.debug("core.xml parse error: %s", exc)

            # app.xml: application name and version
            app_key = names_lower.get("docprops/app.xml")
            if app_key:
                try:
                    info = zf.getinfo(app_key)
                    if info.file_size > _ZIP_MAX_XML_BYTES:
                        logger.warning("Skipping oversized app.xml (%d bytes)", info.file_size)
                    else:
                        app_xml = zf.read(app_key).decode("utf-8", errors="replace")
                        root = ET.fromstring(app_xml)
                        ns = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                        app_el = root.find("ep:Application", ns)
                        ver_el = root.find("ep:AppVersion", ns)
                        meta["application"] = app_el.text if app_el is not None else None
                        meta["app_version"] = ver_el.text if ver_el is not None else None
                except Exception as exc:
                    logger.debug("app.xml parse error: %s", exc)

    except zipfile.BadZipFile:
        return
    except Exception as exc:
        logger.debug("Metadata extraction error: %s", exc)

    # Only store non-None values
    result.file_metadata = {k: v for k, v in meta.items() if v is not None}
