"""Windows ACL policy. pywin32 is required on Windows; no chmod fallback."""
from pathlib import Path, PureWindowsPath
import stat

from services.remote_sensor_models import RemoteSensorError

SYSTEM = 'S-1-5-18'
ADMINISTRATORS = 'S-1-5-32-544'
LOCAL_SERVICE = 'S-1-5-19'
TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
SECRET_TRUSTEES = frozenset({SYSTEM, ADMINISTRATORS, LOCAL_SERVICE})
CODE_TRUSTEES = frozenset({SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER})
# Write data/append/EA/attributes, delete-child/delete, change ACL/owner, generic write/all.
WRITE_MASK = 0x00000156 | 0x000D0000 | 0x50000000


def _api():
    try:
        import win32security
        return win32security
    except ImportError as exc:
        raise RemoteSensorError('Windows sensor requires the operator-installed pywin32 package.') from exc


def validate_local_path(value):
    path = PureWindowsPath(str(value))
    if (not path.is_absolute() or not path.drive.endswith(':') or len(path.drive) != 2
            or '..' in path.parts or ':' in str(path)[2:] or any(c in str(path) for c in '\r\n\x00')):
        raise RemoteSensorError('Windows sensor paths must be absolute local drive paths without streams or traversal.')
    return path


def validate_acl(owner, entries, *, secret):
    """Evaluate normalized ACEs; intentionally reject unfamiliar ACE forms."""
    trusted = SECRET_TRUSTEES if secret else CODE_TRUSTEES
    if owner not in trusted or entries is None or not entries:
        raise RemoteSensorError('Windows file owner or ACL is not trusted.')
    for ace_type, flags, mask, sid in entries:
        if ace_type not in {0, 1}:  # ACCESS_ALLOWED_ACE_TYPE / ACCESS_DENIED_ACE_TYPE
            raise RemoteSensorError('Unsupported Windows ACL entry.')
        if ace_type == 1 or flags & 0x08:  # deny, or inherit-only ACE
            continue
        if sid not in trusted and (mask if secret else mask & WRITE_MASK):
            raise RemoteSensorError('Windows file ACL grants access to an untrusted identity.')


def _check_acl(path, *, secret):
    security = _api()
    try:
        info = security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
                                            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
        dacl = info.GetSecurityDescriptorDacl()
        entries = None if dacl is None else [
            (ace[0][0], ace[0][1], ace[1], security.ConvertSidToStringSid(ace[2]))
            for ace in (dacl.GetAce(i) for i in range(dacl.GetAceCount()))]
        validate_acl(security.ConvertSidToStringSid(info.GetSecurityDescriptorOwner()), entries, secret=secret)
    except RemoteSensorError:
        raise
    except Exception as exc:
        raise RemoteSensorError('Windows ACL could not be verified.') from exc


def assert_no_reparse(path):
    validate_local_path(path)
    for item in (Path(path), *Path(path).parents):
        try:
            if item.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise RemoteSensorError('Windows sensor paths must not contain reparse points.')
        except OSError as exc:
            raise RemoteSensorError('Windows sensor path is unavailable.') from exc


def assert_secret(path):
    assert_no_reparse(path)
    _check_acl(path, secret=True)
    _check_acl(Path(path).parent, secret=True)


def assert_code(path):
    assert_no_reparse(path)
    # Verify ancestors too: a protected binary inside a replaceable directory is unsafe.
    for item in (Path(path), *Path(path).parents):
        if item == Path(item.anchor):
            break
        _check_acl(item, secret=False)


def protect_secret(path):
    """Apply native ACL before any secret bytes are written to a new file."""
    security = _api()
    try:
        import win32api
        import win32con
        token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            user = security.GetTokenInformation(token, security.TokenUser)[0]
            owner = security.ConvertSidToStringSid(user)
            if owner != LOCAL_SERVICE:
                admin = security.ConvertStringSidToSid(ADMINISTRATORS)
                if not security.CheckTokenMembership(None, admin):
                    raise RemoteSensorError('Windows provisioning requires an administrator or LocalService.')
                owner = ADMINISTRATORS
        finally:
            token.Close()
        dacl = security.ACL()
        for sid in sorted(SECRET_TRUSTEES):
            dacl.AddAccessAllowedAce(security.ACL_REVISION, 0x1F01FF,
                                     security.ConvertStringSidToSid(sid))
        security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
            security.ConvertStringSidToSid(owner), None, dacl, None)
        assert_secret(path)
    except RemoteSensorError:
        raise
    except Exception as exc:
        raise RemoteSensorError('Windows file protection could not be applied.') from exc
