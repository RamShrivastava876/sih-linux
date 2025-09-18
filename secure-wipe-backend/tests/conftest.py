import os, tempfile
import pytest

@pytest.fixture(scope='function')
def temp_file_random():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    # write ~2MB random
    size = 2 * 1024 * 1024
    with open(path, 'wb') as f:
        f.write(os.urandom(size))
    yield path
    try: os.remove(path)
    except Exception: pass

@pytest.fixture(scope='function')
def temp_file_zero():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    size = 2 * 1024 * 1024
    with open(path, 'wb') as f:
        f.write(b'\x00' * size)
    yield path
    try: os.remove(path)
    except Exception: pass
