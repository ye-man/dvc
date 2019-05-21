from subprocess import check_call
import shutil
import os
import tempfile

import pytest

from dvc.main import main
from dvc.config import Config
from dvc.remote.gdrive import RemoteGDrive


oauth2_storage = os.path.join(
    Config.get_global_config_dir(),
    "gdrive-oauth2",
    "068b8e92002dd24414a9995a80726a14",
)
if not os.path.exists(oauth2_storage):
    pytest.skip(
        "skipping GDrive tests: could decrypt access token only in Travis",
        allow_module_level=True,
    )


@pytest.mark.parametrize(
    "base_url", ["gdrive://root/", "gdrive://appDataFolder/"]
)
def test_gdrive_push_pull(repo_dir, dvc_repo, base_url):
    dirname = tempfile.mktemp("", "dvc_test_", "")
    url = base_url + dirname
    files = [repo_dir.FOO, repo_dir.DATA_SUB.split(os.path.sep)[0]]

    gdrive = RemoteGDrive(dvc_repo, {"url": url, "oauth_id": "test"})

    # push files
    check_call(["dvc", "add"] + files)
    check_call(["dvc", "remote", "add", "gdrive", url])
    check_call(["dvc", "config", 'remote "gdrive".oauth_id', "test"])
    assert main(["push", "-r", "gdrive"]) == 0

    paths = dvc_repo.cache.local.list_cache_paths()
    paths = [i.parts[-2:] for i in paths]

    # check that files are correctly uploaded
    testdir_meta = gdrive.get_metadata(gdrive.path_info)
    q = "'{}' in parents".format(testdir_meta["id"])
    found = list(gdrive.search(add_params={"q": q}))
    assert set(i["name"] for i in found) == set([i[0] for i in paths])
    q = " or ".join("'{}' in parents".format(i["id"]) for i in found)
    found = list(gdrive.search(add_params={"q": q}))
    assert set(i["name"] for i in found) == set(i[1] for i in paths)

    # remove cache and files
    shutil.rmtree(".dvc/cache")
    for i in files:
        if os.path.isdir(i):
            shutil.rmtree(i)
        else:
            os.remove(i)

    # check that they are in list_cache_paths
    assert set(gdrive.list_cache_paths()) == {
        "/".join([dirname] + list(i)) for i in paths
    }

    # pull them back from remote
    assert main(["pull", "-r", "gdrive"]) == 0

    assert set(files) < set(os.listdir("."))

    # remove the temporary directory on Google Drive
    resp = gdrive.request("DELETE", "drive/v3/files/" + testdir_meta["id"])
    print("Delete temp dir: HTTP {}".format(resp.status_code))
