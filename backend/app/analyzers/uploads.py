import io
import zipfile

from werkzeug.utils import secure_filename

from app.analyzers.manifest import ManifestError, parse_manifest

MAX_MANIFEST_SIZE = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED = 16 * 1024 * 1024


def read_uploaded_manifest(filename, content, restrictions=None):
    restrictions = restrictions or {}
    upload_limit = restrictions.get("upload_limit_mb", 16) * 1024 * 1024
    manifest_limit = restrictions.get("manifest_limit_mb", 2) * 1024 * 1024
    max_entries = restrictions.get("zip_entry_limit", MAX_ZIP_ENTRIES)
    max_expanded = restrictions.get("zip_expanded_size_mb", 16) * 1024 * 1024
    safe_name = secure_filename(filename or "")
    if not safe_name or len(content) > upload_limit:
        raise ManifestError(f"Upload a named manifest.json or ZIP archive within the {upload_limit // (1024 * 1024)} MB configured limit.")
    if safe_name.lower().endswith(".json"):
        if len(content) > manifest_limit:
            raise ManifestError(f"manifest.json must be {manifest_limit // (1024 * 1024)} MB or smaller.")
        parsed = parse_manifest(content)
        return parsed, safe_name
    if not safe_name.lower().endswith(".zip"):
        raise ManifestError("Only manifest.json files and ZIP archives are supported.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except (zipfile.BadZipFile, OSError) as error:
        raise ManifestError("The uploaded ZIP archive is invalid.") from error
    with archive:
        entries = archive.infolist()
        if len(entries) > max_entries:
            raise ManifestError("The ZIP archive contains too many entries.")
        total_size = 0
        manifests = []
        for entry in entries:
            path = entry.filename.replace("\\", "/")
            parts = path.split("/")
            if path.startswith("/") or any(part in ("..", "") for part in parts if part != "") or (parts and ":" in parts[0]):
                raise ManifestError("The ZIP archive contains an unsafe path.")
            if entry.flag_bits & 0x1:
                raise ManifestError("Password-protected ZIP archives are not supported.")
            if entry.is_dir():
                continue
            total_size += entry.file_size
            if total_size > max_expanded or entry.file_size > manifest_limit:
                raise ManifestError("The ZIP archive expands beyond the allowed size.")
            if entry.file_size and entry.compress_size == 0:
                raise ManifestError("The ZIP archive contains an invalid compressed entry.")
            if entry.compress_size and entry.file_size / entry.compress_size > 200:
                raise ManifestError("The ZIP archive has an unsafe compression ratio.")
            if parts[-1].lower() == "manifest.json":
                manifests.append(entry)
        if len(manifests) != 1:
            raise ManifestError("The ZIP archive must contain exactly one manifest.json.")
        try:
            manifest_bytes = archive.read(manifests[0])
        except (RuntimeError, zipfile.BadZipFile, OSError) as error:
            raise ManifestError("Could not read manifest.json from the ZIP archive.") from error
        return parse_manifest(manifest_bytes), safe_name
