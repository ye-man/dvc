from __future__ import unicode_literals

from time import sleep
import posixpath
import os
import logging

try:
    import google_auth_oauthlib
    from .oauth2 import OAuth2
except ImportError:
    google_auth_oauthlib = None

from requests import ConnectionError

from funcy import cached_property

from dvc.scheme import Schemes
from dvc.path_info import CloudURLInfo
from dvc.remote.base import RemoteBASE
from dvc.config import Config
from dvc.progress import progress
from dvc.remote.gdrive.utils import (
    TrackFileReadProgress,
    only_once,
    response_error_message,
    response_is_ratelimit,
    MIME_GOOGLE_APPS_FOLDER,
    metadata_isdir,
)
from dvc.remote.gdrive.exceptions import (
    GDriveError,
    GDriveHTTPError,
    GDriveResourceNotFound,
)


logger = logging.getLogger(__name__)


class GDriveURLInfo(CloudURLInfo):
    @property
    def netloc(self):
        return self.parsed.netloc


class RemoteGDrive(RemoteBASE):
    """Google Drive remote implementation

    ## Some notes on Google Drive design

    Google Drive differs from S3 and GS remotes - it identifies the resources
    by IDs instead of paths.

    Folders are regular resources with an `application/vnd.google-apps.folder`
    MIME type. Resource can have multiple parent folders, and also there could
    be multiple resources with the same name linked to a single folder, so
    files could be duplicated.

    There are multiple root folders accessible from a single user account:
    - `root` (special ID) - alias for the "My Drive" folder
    - `appDataFolder` (special ID) - alias for the hidden application
    space root folder
    - shared drives root folders

    ## Example URLs

    - Datasets/my-dataset inside "My Drive" folder:

        gdrive://root/Datasets/my-dataset

    - Folder by ID (recommended):

        gdrive://1r3UbnmS5B4-7YZPZmyqJuCxLVps1mASC

        (get it https://drive.google.com/drive/folders/{here})

    - Dataset named "my-dataset" in the hidden application folder:

        gdrive://appDataFolder/my-dataset

        (this one wouldn't be visible through Google Drive web UI and
         couldn't be shared)
    """

    scheme = Schemes.GDRIVE
    path_cls = GDriveURLInfo
    REGEX = r"^gdrive://.*$"
    REQUIRES = {"google-auth-oauthlib": google_auth_oauthlib}
    PARAM_CHECKSUM = "md5Checksum"
    GOOGLEAPIS_BASE_URL = "https://www.googleapis.com/"
    SPACE_DRIVE = "drive"
    SCOPE_DRIVE = "https://www.googleapis.com/auth/drive"
    SPACE_APPDATA = "appDataFolder"
    SCOPE_APPDATA = "https://www.googleapis.com/auth/drive.appdata"
    TIMEOUT = (5, 60)

    # Default credential is needed to show the string of "Data Version
    # Control" in OAuth dialog application name and icon in authorized
    # applications list in Google account security settings. Also, the
    # quota usage is limited by the application defined by client_id.
    # The good practice would be to suggest the user to create their
    # own application credentials.
    DEFAULT_CREDENTIALPATH = os.path.join(
        os.path.dirname(__file__), "google-dvc-client-id.json"
    )

    def __init__(self, repo, config):
        super(RemoteGDrive, self).__init__(repo, config)
        self.path_info = self.path_cls(config[Config.SECTION_REMOTE_URL])
        self.root = self.path_info.netloc.lower()
        if self.root == self.SPACE_APPDATA.lower():
            default_scopes = self.SCOPE_APPDATA
            self.space = self.SPACE_APPDATA
        else:
            default_scopes = self.SCOPE_DRIVE
            self.space = self.SPACE_DRIVE
        if Config.SECTION_GDRIVE_CREDENTIALPATH not in config:
            logger.warning(
                "Warning: a shared GoogleAPI token is in use. "
                "Please create your own token."
            )
        credentialpath = config.get(
            Config.SECTION_GDRIVE_CREDENTIALPATH, self.DEFAULT_CREDENTIALPATH
        )
        scopes = config.get(Config.SECTION_GDRIVE_SCOPES, default_scopes)
        # scopes should be a list and it is space-delimited in all
        # configs, and `.split()` also works for a single-element list
        scopes = scopes.split()
        self.oauth2 = OAuth2(
            config.get(Config.SECTION_GDRIVE_OAUTH_ID, "default"),
            credentialpath,
            scopes,
            self.repo.config.config[Config.SECTION_CORE],
        )
        self.max_retries = 10

    @cached_property
    def session(self):
        """AuthorizedSession to communicate with https://googleapis.com

        Security notice:

        It always adds the Authorization header to the requests, not paying
        attention is request is for googleapis.com or not. It is just how
        AuthorizedSession from google-auth implements adding its headers. Don't
        use RemoteGDrive.session() to send requests to domains other than
        googleapis.com.
        """
        return self.oauth2.get_session()

    def request(self, method, path, *args, **kwargs):
        # Google Drive has tight rate limits, which strikes the
        # performance and gives the 403 and 429 errors.
        # See https://developers.google.com/drive/api/v3/handle-errors
        retries = 0
        exponential_backoff = 1
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.TIMEOUT
        while retries < self.max_retries:
            retries += 1
            response = self.session.request(
                method, self.GOOGLEAPIS_BASE_URL + path, *args, **kwargs
            )
            if response_is_ratelimit(response) or response.status_code >= 500:
                logger.debug(
                    "got {} response, will retry in {} sec".format(
                        response.status_code, exponential_backoff
                    )
                )
                sleep(exponential_backoff)
                exponential_backoff *= 2
            else:
                break
        if response.status_code >= 400:
            raise GDriveHTTPError(response)
        return response

    def search(self, parent=None, name=None, add_params={}):
        query = []
        if parent is not None:
            query.append("'{}' in parents".format(parent))
        if name is not None:
            query.append("name = '{}'".format(name))
        params = {"q": " and ".join(query), "spaces": self.space}
        params.update(add_params)
        while True:
            data = self.request("GET", "drive/v3/files", params=params).json()
            for i in data["files"]:
                yield i
            if not data.get("nextPageToken"):
                break
            params["pageToken"] = data["nextPageToken"]

    def get_metadata(self, path_info, fields=None):
        parent = self.request(
            "GET", "drive/v3/files/" + path_info.netloc
        ).json()
        current_path = ["gdrive://" + path_info.netloc]
        parts = path_info.path.split("/")
        kwargs = [{} for i in parts]
        if fields is not None:
            # only specify fields for the last search query
            kwargs[-1]["add_params"] = {
                "fields": "files({})".format(",".join(fields))
            }
        for part, kwargs in zip(parts, kwargs):
            if not metadata_isdir(parent):
                raise GDriveError(
                    "{} is not a folder".format("/".join(current_path))
                )
            current_path.append(part)
            files = list(self.search(parent["id"], part, **kwargs))
            if len(files) > 1:
                raise GDriveError(
                    "path {} is duplicated".format("/".join(current_path))
                )
            elif len(files) == 0:
                raise GDriveResourceNotFound("/".join(current_path))
            parent = files[0]
        return parent

    def get_file_checksum(self, path_info):
        metadata = self.get_metadata(path_info, fields=["md5Checksum"])
        return metadata["md5Checksum"]

    def exists(self, path_info):
        try:
            self.get_metadata(path_info, fields=[])
            return True
        except GDriveResourceNotFound:
            return False

    def batch_exists(self, path_infos, callback):
        results = []

        for path_info in path_infos:
            results.append(self.exists(path_info))
            callback.update(str(path_info))

        return results

    def _list_files(self, folder_id):
        for i in self.search(parent=folder_id):
            if metadata_isdir(i):
                for j in self._list_files(i["id"]):
                    yield i["name"] + "/" + j
            else:
                yield i["name"]

    def list_cache_paths(self):
        try:
            root = self.get_metadata(self.path_info)
        except GDriveResourceNotFound as e:
            logger.debug("list_cache_paths: {}".format(e))
        else:
            prefix = self.path_info.path
            for i in self._list_files(root["id"]):
                yield prefix + "/" + i

    @only_once
    def mkdir(self, parent, name):
        data = {
            "name": name,
            "mimeType": MIME_GOOGLE_APPS_FOLDER,
            "parents": [parent],
            "spaces": self.space,
        }
        return self.request("POST", "drive/v3/files", json=data).json()

    def makedirs(self, path_info):
        parent = path_info.netloc
        parts = iter(path_info.path.split("/"))
        current_path = ["gdrive://" + path_info.netloc]
        for part in parts:
            try:
                metadata = self.get_metadata(
                    self.path_cls.from_parts(
                        self.scheme, parent, path="/" + part
                    )
                )
            except GDriveResourceNotFound:
                break
            else:
                current_path.append(part)
                if not metadata_isdir(metadata):
                    raise GDriveError(
                        "{} is not a folder".format("/".join(current_path))
                    )
                parent = metadata["id"]
        to_create = [part] + list(parts)
        for part in to_create:
            parent = self.mkdir(parent, part)["id"]
        return parent

    def _resumable_upload_initiate(self, parent, filename):
        response = self.request(
            "POST",
            "upload/drive/v3/files",
            params={"uploadType": "resumable"},
            json={"name": filename, "space": self.space, "parents": [parent]},
        )
        return response.headers["Location"]

    def _resumable_upload_first_request(
        self, resumable_upload_url, from_file, to_info, file_size
    ):
        try:
            # outside of self.request() because this process
            # doesn't need it to handle errors and retries,
            # they are handled in the next "while" loop
            response = self.session.put(
                resumable_upload_url,
                data=from_file,
                headers={"Content-Length": str(file_size)},
                timeout=self.TIMEOUT,
            )
            return response.status_code in (200, 201)
        except ConnectionError:
            return False

    def _resumable_upload_resume(
        self, resumable_upload_url, from_file, to_info, file_size
    ):
        # determine the offset
        response = self.session.put(
            resumable_upload_url,
            headers={
                "Content-Length": str(0),
                "Content-Range": "bytes */{}".format(file_size),
            },
            timeout=self.TIMEOUT,
        )
        if response.status_code in (200, 201):
            # file has been already uploaded
            return True
        elif response.status_code == 404:
            # restarting upload from the beginning wouldn't make a
            # profit, so it is better to notify the user
            raise GDriveError("upload failed, try again")
        elif response.status_code != 308:
            logger.error(
                "upload resume failure: {}".format(
                    response_error_message(response)
                )
            )
            return False
        # ^^ response.status_code is 308 (Resume Incomplete) - continue
        # the upload

        if "Range" in response.headers:
            # if Range header contains a string "bytes 0-9/20"
            # then the server has received the bytes from 0 to 9
            # (including the ends), so upload should be resumed from
            # byte 10
            offset = int(response.headers["Range"].split("-")[-1]) + 1
        else:
            # there could be no Range header in the server response,
            # then upload should be resumed from start
            offset = 0
        logger.debug(
            "resuming {} upload from offset {}".format(to_info, offset)
        )

        # resume the upload
        from_file.seek(offset, 0)
        response = self.session.put(
            resumable_upload_url,
            data=from_file,
            headers={
                "Content-Length": str(file_size - offset),
                "Content-Range": "bytes {}-{}/{}".format(
                    offset, file_size - 1, file_size
                ),
            },
            timeout=self.TIMEOUT,
        )
        return response.status_code in (200, 201)

    def _upload(self, from_file, to_info, name, ctx, no_progress_bar):

        dirname = to_info.parent.path
        if dirname:
            try:
                parent = self.get_metadata(to_info.parent)
            except GDriveResourceNotFound:
                parent = self.makedirs(to_info.parent)
        else:
            parent = to_info.netloc

        from_file = open(from_file, "rb")
        if not no_progress_bar:
            from_file = TrackFileReadProgress(name, from_file)

        file_size = os.fstat(from_file.fileno()).st_size

        try:
            # Resumable upload protocol implementation
            # https://developers.google.com/drive/api/v3/manage-uploads#resumable
            resumable_upload_url = self._resumable_upload_initiate(
                parent, posixpath.basename(to_info.path)
            )
            success = self._resumable_upload_first_request(
                resumable_upload_url, from_file, to_info, file_size
            )
            errors_count = 0
            while not success:
                try:
                    success = self._resumable_upload_resume(
                        resumable_upload_url, from_file, to_info, file_size
                    )
                except ConnectionError:
                    errors_count += 1
                    if errors_count >= 10:
                        raise
                    sleep(1.0)
        finally:
            from_file.close()

    def _download(
        self, from_info, to_file, name, ctx, resume, no_progress_bar
    ):
        metadata = self.get_metadata(
            from_info, fields=["id", "mimeType", "size"]
        )
        response = self.request(
            "GET",
            "drive/v3/files/" + metadata["id"],
            params={"alt": "media"},
            stream=True,
        )
        current = 0
        if response.status_code != 200:
            raise GDriveHTTPError(response)
        with open(to_file, "wb") as f:
            for chunk in response.iter_content(4096):
                f.write(chunk)
                if not no_progress_bar:
                    current += len(chunk)
                    progress.update_target(name, current, metadata["size"])
