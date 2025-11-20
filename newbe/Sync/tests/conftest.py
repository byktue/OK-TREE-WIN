import sys
from pathlib import Path
import shutil
import pytest


@pytest.fixture(scope='session')
def repo_root():
    p = Path(__file__).resolve().parent
    # repo root is one level up from tests
    return p.parent

@pytest.fixture(scope='session')
def data_root(repo_root):
    # data is stored under the shared repository root (newbe/data)
    return repo_root.parent / 'data'


@pytest.fixture(autouse=True)
def module_path(repo_root):
    """Ensure Module is importable during tests."""
    module_path = repo_root / 'Module'
    s = str(module_path)
    if s not in sys.path:
        sys.path.insert(0, s)


def _clean_blocks(data_root: Path):
    bdir = data_root / 'server_storage' / 'blocks'
    if bdir.exists():
        for p in bdir.glob('*'):
            try:
                p.unlink()
            except Exception:
                pass


def _clean_user_uploads(data_root: Path, username: str = 'test'):
    user_dir = data_root / 'server_storage' / 'sync_uploads' / username
    if not user_dir.exists():
        return
    # remove files produced by tests (prefix patterns)
    for p in list(user_dir.glob('verify_*')) + list(user_dir.glob('large_*')) + list(user_dir.glob('small*')) + list(user_dir.glob('sync_test_*')):
        try:
            if p.is_file():
                p.unlink()
            else:
                shutil.rmtree(p)
        except Exception:
            pass


@pytest.fixture(autouse=True)
def clean_env(repo_root, data_root):
    """Auto-clean relevant server storage locations before each test for reproducibility."""
    _clean_blocks(data_root)
    _clean_user_uploads(data_root, username='test')
    # Also ensure verify_sync_folder and test_sync_folder are fresh
    v = repo_root / 'verify_sync_folder'
    if v.exists():
        for p in v.glob('*'):
            try:
                if p.is_file():
                    p.unlink()
                else:
                    shutil.rmtree(p)
            except Exception:
                pass
    ts = repo_root / 'test_sync_folder'
    if ts.exists():
        for p in ts.glob('*'):
            try:
                if p.is_file():
                    p.unlink()
                else:
                    shutil.rmtree(p)
            except Exception:
                pass

    yield

    # post-test cleanup (best-effort)
    _clean_blocks(repo_root)
    _clean_user_uploads(repo_root, username='test')