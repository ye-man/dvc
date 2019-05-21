from datetime import datetime, timedelta
import json

import mock

import pytest

import requests

import google.oauth2.credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from dvc.repo import Repo
from dvc.remote.gdrive import RemoteGDrive, GDriveError, GDriveResourceNotFound
from dvc.remote.gdrive.oauth2 import OAuth2
from dvc.remote.gdrive.utils import (
    response_error_message,
    response_is_ratelimit,
    MIME_GOOGLE_APPS_FOLDER,
)


GDRIVE_URL = "gdrive://root/data"
AUTHORIZATION = {"authorization": "Bearer MOCK_token"}
FOLDER = {"mimeType": MIME_GOOGLE_APPS_FOLDER}
FILE = {"mimeType": "not-a-folder"}

COMMON_KWARGS = {
    "data": None,
    "headers": AUTHORIZATION,
    "timeout": RemoteGDrive.TIMEOUT,
}


class Response:
    def __init__(self, data, status_code=200):
        self._data = data
        self.text = json.dumps(data) if isinstance(data, dict) else data
        self.status_code = status_code

    def json(self):
        return self._data


@pytest.fixture()
def repo():
    return Repo(".")


@pytest.fixture
def gdrive(repo):
    return RemoteGDrive(repo, {"url": GDRIVE_URL})


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    mocked = mock.Mock(return_value=Response("test"))
    monkeypatch.setattr("requests.sessions.Session.request", mocked)
    return mocked


@pytest.fixture()
def mocked_get_metadata(gdrive, monkeypatch):
    mocked = mock.Mock(
        gdrive.get_metadata,
        return_value=dict(id="root", name="root", **FOLDER),
    )
    monkeypatch.setattr(gdrive, "get_metadata", mocked)
    return mocked


@pytest.fixture()
def mocked_search(gdrive, monkeypatch):
    mocked = mock.Mock(gdrive.search)
    monkeypatch.setattr(gdrive, "search", mocked)
    return mocked


def _url(url):
    return RemoteGDrive.GOOGLEAPIS_BASE_URL + url


def _p(root, path):
    return RemoteGDrive.path_cls.from_parts(
        "gdrive", netloc=root, path="/" + path
    )


@pytest.fixture(autouse=True)
def fake_creds(monkeypatch):

    creds = google.oauth2.credentials.Credentials(
        token="MOCK_token",
        refresh_token="MOCK_refresh_token",
        token_uri="MOCK_token_uri",
        client_id="MOCK_client_id",
        client_secret="MOCK_client_secret",
        scopes=["MOCK_scopes"],
    )
    creds.expiry = datetime.now() + timedelta(days=1)

    mocked_flow = mock.Mock()
    mocked_flow.run_console.return_value = creds
    mocked_flow.run_local_server.return_value = creds

    monkeypatch.setattr(
        InstalledAppFlow,
        "from_client_secrets_file",
        classmethod(lambda *args, **kwargs: mocked_flow),
    )

    monkeypatch.setattr(
        OAuth2, "_get_creds_id", mock.Mock(return_value="test")
    )


@pytest.fixture(autouse=True)
def no_refresh(monkeypatch):
    expired_mock = mock.PropertyMock(return_value=False)
    monkeypatch.setattr(
        "google.oauth2.credentials.Credentials.expired", expired_mock
    )
    refresh_mock = mock.Mock()
    monkeypatch.setattr(
        "google.oauth2.credentials.Credentials.refresh", refresh_mock
    )
    return refresh_mock, expired_mock


@pytest.fixture()
def makedirs(gdrive, monkeypatch):
    mocked = mock.Mock(gdrive.makedirs, return_value="FOLDER_ID")
    monkeypatch.setattr(gdrive, "makedirs", mocked)
    return mocked


def test_init_drive(gdrive):
    assert gdrive.root == "root"
    assert str(gdrive.path_info) == GDRIVE_URL
    assert gdrive.oauth2.scopes == ["https://www.googleapis.com/auth/drive"]
    assert gdrive.space == RemoteGDrive.SPACE_DRIVE


def test_init_appfolder(repo):
    url = "gdrive://appdatafolder/data"
    gdrive = RemoteGDrive(repo, {"url": url})
    assert gdrive.root == "appdatafolder"
    assert str(gdrive.path_info) == url
    assert gdrive.oauth2.scopes == [
        "https://www.googleapis.com/auth/drive.appdata"
    ]
    assert gdrive.space == RemoteGDrive.SPACE_APPDATA


def test_init_folder_id(repo):
    url = "gdrive://folder_id/data"
    gdrive = RemoteGDrive(repo, {"url": url})
    assert gdrive.root == "folder_id"
    assert str(gdrive.path_info) == url
    assert gdrive.oauth2.scopes == ["https://www.googleapis.com/auth/drive"]
    assert gdrive.space == "drive"


def test_get_session(gdrive, no_requests):
    session = gdrive.oauth2.get_session()
    session.get("http://httpbin.org/get")
    args, kwargs = no_requests.call_args
    assert kwargs["headers"]["authorization"] == AUTHORIZATION["authorization"]


def test_response_is_ratelimit(gdrive):
    assert response_is_ratelimit(
        Response({"error": {"errors": [{"domain": "usageLimits"}]}}, 403)
    )
    assert not response_is_ratelimit(Response(""))


def test_response_error_message(gdrive):
    r = Response({"error": {"message": "test"}})
    assert response_error_message(r) == "HTTP 200: test"
    r = Response("test")
    assert response_error_message(r) == "HTTP 200: test"


def test_request(gdrive, no_requests):
    assert gdrive.request("GET", "test").text == "test"
    no_requests.assert_called_once_with("GET", _url("test"), **COMMON_KWARGS)


def test_request_refresh(gdrive, no_requests, no_refresh):
    refresh_mock, _ = no_refresh
    no_requests.side_effect = [
        Response("error", 401),
        Response("after_refresh", 200),
    ]
    assert gdrive.request("GET", "test").text == "after_refresh"
    refresh_mock.assert_called_once()
    assert no_requests.mock_calls == [
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
    ]


def test_request_expired(gdrive, no_requests, no_refresh):
    refresh_mock, expired_mock = no_refresh
    expired_mock.side_effect = [True, False]
    no_requests.side_effect = [Response("test", 200)]
    assert gdrive.request("GET", "test").text == "test"
    expired_mock.assert_called()
    refresh_mock.assert_called_once()
    assert no_requests.mock_calls == [
        mock.call("GET", _url("test"), **COMMON_KWARGS)
    ]


def test_request_retry_and_backoff(gdrive, no_requests, monkeypatch):
    no_requests.side_effect = [
        Response("error", 500),
        Response("error", 500),
        Response("retry", 200),
    ]
    sleep_mock = mock.Mock()
    monkeypatch.setattr("dvc.remote.gdrive.sleep", sleep_mock)
    assert gdrive.request("GET", "test").text == "retry"
    assert no_requests.mock_calls == [
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
    ]
    assert sleep_mock.mock_calls == [mock.call(1), mock.call(2)]


def test_request_4xx(gdrive, no_requests):
    no_requests.return_value = Response("error", 400)
    with pytest.raises(GDriveError):
        gdrive.request("GET", "test")


def test_search(gdrive, no_requests):
    no_requests.side_effect = [
        Response({"files": ["test1"], "nextPageToken": "TEST_nextPageToken"}),
        Response({"files": ["test2"]}),
    ]
    assert list(gdrive.search("test", "root")) == ["test1", "test2"]


def test_metadata_by_path(gdrive, no_requests):
    no_requests.side_effect = [
        Response(dict(id="root", name="root", **FOLDER)),
        Response({"files": [dict(id="id1", name="path1", **FOLDER)]}),
        Response({"files": [dict(id="id2", name="path2", **FOLDER)]}),
    ]
    gdrive.get_metadata(_p("root", "path1/path2"), ["field1", "field2"])
    assert no_requests.mock_calls == [
        mock.call("GET", _url("drive/v3/files/root"), **COMMON_KWARGS),
        mock.call(
            "GET",
            _url("drive/v3/files"),
            params={
                "q": "'root' in parents and name = 'path1'",
                "spaces": "drive",
            },
            **COMMON_KWARGS
        ),
        mock.call(
            "GET",
            _url("drive/v3/files"),
            params={
                "q": "'id1' in parents and name = 'path2'",
                "spaces": "drive",
                "fields": "files(field1,field2)",
            },
            **COMMON_KWARGS
        ),
    ]


def test_metadata_by_path_not_a_folder(gdrive, no_requests, mocked_search):
    no_requests.return_value = Response(dict(id="id1", name="root", **FOLDER))
    mocked_search.return_value = [dict(id="id2", name="path1", **FILE)]
    with pytest.raises(GDriveError):
        gdrive.get_metadata(_p("root", "path1/path2"), ["field1", "field2"])
    gdrive.get_metadata(_p("root", "path1"), ["field1", "field2"])


def test_metadata_by_path_duplicate(gdrive, no_requests, mocked_search):
    no_requests.return_value = Response(dict(id="id1", name="root", **FOLDER))
    mocked_search.return_value = [
        dict(id="id2", name="path1", **FOLDER),
        dict(id="id3", name="path1", **FOLDER),
    ]
    with pytest.raises(GDriveError):
        gdrive.get_metadata(_p("root", "path1/path2"), ["field1", "field2"])


def test_metadata_by_path_not_found(gdrive, no_requests, mocked_search):
    no_requests.return_value = Response(dict(id="root", name="root", **FOLDER))
    mocked_search.return_value = []
    with pytest.raises(GDriveResourceNotFound):
        gdrive.get_metadata(_p("root", "path1/path2"), ["field1", "field2"])


def test_get_file_checksum(gdrive, mocked_get_metadata):
    mocked_get_metadata.return_value = dict(
        id="id1", name="path1", md5Checksum="checksum"
    )
    checksum = gdrive.get_file_checksum(_p(gdrive.root, "path1"))
    assert checksum == "checksum"
    mocked_get_metadata.assert_called_once_with(
        _p(gdrive.root, "path1"), fields=["md5Checksum"]
    )


def test_list_cache_paths(gdrive, mocked_get_metadata, mocked_search):
    mocked_get_metadata.return_value = dict(id="root", name="root", **FOLDER)
    mocked_search.side_effect = [
        [dict(id="f1", name="f1", **FOLDER), dict(id="f2", name="f2", **FILE)],
        [dict(id="f3", name="f3", **FILE)],
    ]
    assert list(gdrive.list_cache_paths()) == ["data/f1/f3", "data/f2"]
    mocked_get_metadata.assert_called_once_with(_p("root", "data"))


def test_list_cache_path_not_found(gdrive, mocked_get_metadata):
    mocked_get_metadata.side_effect = GDriveResourceNotFound("test")
    assert list(gdrive.list_cache_paths()) == []
    mocked_get_metadata.assert_called_once_with(_p("root", "data"))


def test_mkdir(gdrive, no_requests):
    no_requests.return_value = Response("test")
    assert gdrive.mkdir("root", "test") == "test"
    no_requests.assert_called_once_with(
        "POST",
        _url("drive/v3/files"),
        json={
            "name": "test",
            "mimeType": FOLDER["mimeType"],
            "parents": ["root"],
            "spaces": "drive",
        },
        **COMMON_KWARGS
    )


def test_makedirs(gdrive, monkeypatch, mocked_get_metadata):
    mocked_get_metadata.side_effect = [
        dict(id="id1", name="test1", **FOLDER),
        GDriveResourceNotFound("test1/test2"),
    ]
    monkeypatch.setattr(
        gdrive, "mkdir", mock.Mock(side_effect=[{"id": "id2"}])
    )
    assert gdrive.makedirs(_p(gdrive.root, "test1/test2")) == "id2"
    assert gdrive.get_metadata.mock_calls == [
        mock.call(_p(gdrive.root, "test1")),
        mock.call(_p("id1", "test2")),
    ]
    assert gdrive.mkdir.mock_calls == [mock.call("id1", "test2")]


def test_makedirs_error(gdrive, mocked_get_metadata):
    mocked_get_metadata.side_effect = [dict(id="id1", name="test1", **FILE)]
    with pytest.raises(GDriveError):
        gdrive.makedirs(_p(gdrive.root, "test1/test2"))


def test_resumable_upload_first_request(gdrive, no_requests):
    resp = Response("", 201)
    no_requests.return_value = resp
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is True
    )


def test_resumable_upload_first_request_connection_error(gdrive, no_requests):
    no_requests.side_effect = requests.ConnectionError
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is False
    )


def test_resumable_upload_first_request_failure(gdrive, no_requests):
    no_requests.return_value = Response("", 400)
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is False
    )
