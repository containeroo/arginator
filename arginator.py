import logging
import logging.handlers
import os
import re
import sys
from collections import defaultdict, namedtuple
from pathlib import Path
from typing import List

import urllib3

try:
    import gitlab
    import requests
    import semver
    import yaml
    from gitlab import Gitlab
    from gitlab.exceptions import (GitlabAuthenticationError,
                                   GitlabCreateError, GitlabGetError,
                                   GitlabUpdateError, GitlabUploadError)
    from gitlab.v4.objects import (Project, ProjectBranch, ProjectCommit,
                                   ProjectMergeRequest)
except Exception:
    sys.stderr.write("requirements are not satisfied! see 'requirements.txt'\n")
    sys.exit(1)

__version__ = "0.0.1"


Pattern = namedtuple("Pattern", ['target_revision', 'mr_title', ])
pattern = Pattern(
    target_revision="targetRevision: {VERSION}",
    mr_title=r"^(Update {CHART_NAME} chart to )v?(\d+.\d+.\d+).*",
)

Templates = namedtuple("templates", ['branch_name',
                                     'merge_request_title',
                                     'description',
                                     'slack_notification',
                                    ]
)
templates = Templates(
    branch_name="arginator/{CHART_NAME}",
    merge_request_title="Update {CHART_NAME} chart to {NEW_VERSION}",
    description="| Chart | Change |\n"
                "| :-- |:-- |\n"
                "| {NAME} | `{OLD_VERSION}` -> `{NEW_VERSION}`|\n"
                "---\n"
                "### Arginator configuration\n"
                "{CONFIG}",
    slack_notification="{LINK_START}{CHART_NAME}{LINK_END}: `{OLD_VERSION}` -&gt; `{NEW_VERSION}`",
)

Argo = namedtuple("Argo", ['url', 'charts'])


class CallCounted:
    """Decorator to determine number of calls for a method"""

    def __init__(self, method):
        self.method = method
        self.counter = 0

    def __call__(self, *args, **kwargs):
        self.counter += 1
        return self.method(*args, **kwargs)


def check_env_vars() -> namedtuple:
    """check_env_vars parse env vars"""
    ci_dir_project = os.environ.get("CI_PROJECT_DIR")
    search_dir = os.environ.get("ARGINATOR_ROOT_DIR", ci_dir_project)
    enable_prereleases = os.environ.get("ARGINATOR_ENABLE_PRERELEASES", "false").lower() == "true"

    verify_ssl = os.environ.get("ARGINATOR_VERIFY_SSL", "false").lower() == "true"
    loglevel = os.environ.get("ARGINATOR_LOGLEVEL", "info").lower()

    enable_mergerequests = os.environ.get("ARGINATOR_ENABLE_MERGEREQUESTS", "true").lower() == "true"
    gitlab_token = os.environ.get("ARGINATOR_GITLAB_TOKEN")
    remove_source_branch = os.environ.get("ARGINATOR_GITLAB_REMOVE_SOURCE_BRANCH", "true").lower() == "true"
    squash = os.environ.get("ARGINATOR_GITLAB_SQUASH_COMMITS", "false").lower() == "true"
    automerge = os.environ.get("ARGINATOR_GITLAB_AUTOMERGE", "false").lower() == "true"
    merge_major = os.environ.get("ARGINATOR_GITLAB_MERGE_MAJOR", "false").lower() == "true"

    assignees = os.environ.get("ARGINATOR_GITLAB_ASSIGNEES")
    assignees = ([] if not assignees else [a.strip() for a in assignees.split(",") if a])

    labels = os.environ.get("ARGINATOR_GITLAB_LABELS")
    labels = [] if labels == "" else ["arginator"] if labels is None else [l.strip() for l in labels.split(",") if l]

    slack_token = os.environ.get("ARGINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("ARGINATOR_SLACK_CHANNEL")

    gitlab_url = os.environ.get("CI_SERVER_URL")
    project_id = os.environ.get("CI_PROJECT_ID")

    if not project_id:
        raise EnvironmentError("environment variable 'CI_PROJECT_ID' not set!")

    if not str(project_id).isdigit():
        raise EnvironmentError("environment variable 'CI_PROJECT_ID' must be int!")

    if not search_dir:
        raise EnvironmentError("environment variable 'ARGINATOR_ROOT_DIR' not set!")

    if slack_token and not slack_channel:
        raise EnvironmentError("environment variable 'ARGINATOR_SLACK_CHANNEL' not set!")

    if enable_mergerequests and not gitlab_token:
        raise EnvironmentError("environment variable 'GITLAB_TOKEN' not set!")

    Env_vars = namedtuple('Env_vars', ['search_dir',
                                       'enable_prereleases',
                                       'verify_ssl',
                                       'loglevel',
                                       'enable_mergerequests',
                                       'gitlab_token',
                                       'remove_source_branch',
                                       'squash',
                                       'automerge',
                                       'merge_major',
                                       'assignees',
                                       'labels',
                                       'slack_token',
                                       'slack_channel',
                                       'gitlab_url',
                                       'project_id',
                                       ]
    )

    return Env_vars(
        search_dir=search_dir,
        enable_prereleases=enable_prereleases,
        verify_ssl=verify_ssl,
        loglevel=loglevel,
        enable_mergerequests=enable_mergerequests,
        gitlab_token=gitlab_token,
        remove_source_branch=remove_source_branch,
        squash=squash,
        automerge=automerge,
        merge_major=merge_major,
        assignees=assignees,
        labels=labels,
        slack_token=slack_token,
        slack_channel=slack_channel,
        gitlab_url=gitlab_url,
        project_id=int(project_id),
    )


def setup_logger(loglevel: str = 'info'):
    """setup_logger setup logger

    Args:
        loglevel (str, optional): loglevel to set. Defaults to 'info'.
    """
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    urllib3.disable_warnings()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    loglevel = loglevel.lower()
    if loglevel == "critical":
        loglevel = logging.CRITICAL
    elif loglevel == "error":
        loglevel = logging.ERROR
    elif loglevel == "warning":
        loglevel = logging.WARNING
    elif loglevel == "info":
        loglevel = logging.INFO
    elif loglevel == "debug":
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    debug_format = logging.Formatter(
        "%(asctime)s [%(filename)s:%(lineno)s - %(funcName)-20s ] [%(levelname)-7.7s] %(message)s")

    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(debug_format if loglevel == logging.DEBUG else default_format)
    root_logger.addHandler(console_logger)

    logging.error = CallCounted(logging.error)
    logging.critical = CallCounted(logging.critical)


def process_yaml(search_dir: str) -> Argo:
    """process_yaml iterate over yaml files and extract repo URL, Helm chart name and version

    Args:
        search_dir (str): directory to search yml & yaml files

    Raises:
        NotADirectoryError: 'search_dir' is not a directory

    Returns:
        namedTuple: Argo(url=str, charts=List[dict])
                    url: path to helm chart repo
                    charts: dict with following keys:
                            chart_name: name of chart
                            version: current version of chart
                            yaml_path: path to yaml file
    """
    search_dir = Path(search_dir)
    argo_helm_charts = defaultdict(list)

    if not search_dir.is_dir():
        raise NotADirectoryError(f"'{search_dir}' is not a directory")
    for item in search_dir.glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        try:
            with open(item) as stream:
                content = yaml.safe_load(stream)
        except Exception:
            # ignore unparsable yaml files, since argocd already does this
            return
        if not isinstance(content, dict):
            return

        if content.get("kind") != "Application":
            logging.debug(f"skip manifest '{item}' because it is not of kind 'Application'")
            continue
        if content.get("spec") and not content['spec'].get("source"):
            logging.debug(f"skip manifest '{item}' because it does not contain the path 'spec.source'")
            continue
        chart_name = content['spec']['source']['chart']
        repo_url = content['spec']['source']['repoURL']
        version = content['spec']['source']['targetRevision']

        argo_helm_charts[repo_url].append(
            {
                "chart_name": chart_name,
                "version": version,
                "yaml_path": item
            }
        )

    # convert list of tuple to namedTuple (Argo)
    argo_charts = []
    for item in argo_helm_charts.items():
        argo_charts.append(Argo(url=item[0], charts=item[1]))

    return argo_charts


def process_argo_helm_charts(argo_helm_charts: List[Argo]) -> List[dict]:
    """process_argo_helm_charts process found helm charts from argocd manifests

    Args:
        argo_helm_charts (List[Argo]): list of Argo namedTuple

    Returns:
        List[dict]: list of dict with following keys:
            chart_name: name of chart
            old_version: current version of chart from ArgoCD manifest
            new_version: newest available Helm chart version
            yaml_path: path to ArgoCD manifest
    """
    chart_updates = []
    for argo_helm_chart in argo_helm_charts:
        chart_url = argo_helm_chart.url
        try:
            repo_helm_charts = get_helm_chart(chart_url=chart_url)
        except Exception as e:
            logging.error(f"cannot get helm chart from '{chart_url}'. {str(e)}")

        try:
            updates = get_chart_updates(repo_helm_charts=repo_helm_charts,
                                        argo_helm_charts=argo_helm_chart.charts)
            chart_updates.extend(updates)
        except Exception as e:
            logging.error(f"cannot get chart updates for helm chart '{chart_url}'. {str(e)}")

    return chart_updates


def get_helm_chart(chart_url: str, verify_ssl: bool = False) -> dict:
    """get_helm_chart get helm chart from a repo

    Args:
        chart_url (str): URL to helm chart
        verify_ssl (bool, optional): check SSL certificate. Defaults to False.

    Raises:
        urllib3.exceptions.HTTPError: unable to get helm chart
        urllib3.exceptions.ResponseError: http status code is not 200
        urllib3.exceptions.DecodeError: unable to response into a dict

    Returns:
        dict: dictionary with helm chart repos
    """
    chart_url = chart_url.rstrip("/")
    try:
        logging.debug(f"get helm charts from '{chart_url}'")
        chart_url = f"{chart_url}/index.yaml"
        repo_response = requests.get(url=chart_url, verify=verify_ssl)
    except Exception as e:
        raise urllib3.exceptions.HTTPError(f"unable to fetch helm repository '{chart_url}'. {str(e)}")

    if repo_response.status_code != 200:
        raise urllib3.exceptions.ResponseError(f"'{chart_url}' returned: {repo_response.status_code}")

    try:
        repo_charts = yaml.safe_load(repo_response.content)
    except Exception as e:
        raise urllib3.exceptions.DecodeError(f"unable to parse '{chart_url}'. {str(e)}")

    return repo_charts['entries'].items()


def get_chart_updates(repo_helm_charts: dict,
                      argo_helm_charts: List[dict],
                      enable_prereleases: bool = False) -> List[dict]:
    """get_chart_updates search new version in a helm chart

    Args:
        repo_helm_charts (dict): helm chart dict
        argo_helm_charts (List[dict]): list of dict with following keys:
                                       chart_name: name of chart
                                       verion: current version of chart from ArgoCD manifest
                                       yaml_path: path to ArgoCD manifest
        enable_prereleases (bool, optional): [description]. Defaults to False.

    Returns:
        List[dict]: list of dict with following keys:
                    chart_name: name of chart
                    old_version: current version of chart from ArgoCD manifest
                    new_version: newest available Helm chart version
                    yaml_path: path to ArgoCD manifest
    """
    chart_updates = []
    for repo_helm_chart in repo_helm_charts:
        chart_name = repo_helm_chart[0]
        for argo_helm_chart in argo_helm_charts:
            if argo_helm_chart['chart_name'] != chart_name:
                continue
            versions = []
            current_chart_version = argo_helm_chart['version']
            for repo_chart in repo_helm_chart[1]:
                if not semver.VersionInfo.isvalid(repo_chart['version'].lstrip('v')):
                    logging.warning(
                        f"helm chart '{repo_chart['name']}' has an invalid version '{repo_chart['version']}'")
                    continue
                version = semver.VersionInfo.parse(repo_chart['version'].lstrip('v'))
                if version.prerelease and not enable_prereleases:
                    logging.debug(f"skipping version '{repo_chart['version']}' of helm chart "
                                  f"'{repo_chart['name']}' because it is a pre-release")
                    continue
                logging.debug(f"found version '{repo_chart['version']}' of helm chart '{repo_chart['name']}'")
                versions.extend([repo_chart['version']])

            clean_versions = [version.lstrip('v') for version in versions]
            latest_version = str(max(map(semver.VersionInfo.parse, clean_versions)))

            latest_version = [version for version in versions if latest_version in version]

            if semver.match(latest_version[0].lstrip('v'), f">{current_chart_version.lstrip('v')}"):
                repo_chart = {
                    'chart_name': chart_name,
                    'old_version': current_chart_version,
                    'new_version': latest_version[0],
                    'yaml_path': argo_helm_chart['yaml_path']
                }
                chart_updates.append(repo_chart)
                logging.info(f"found update for helm chart '{repo_chart['chart_name']}': "
                             f"'{current_chart_version}' to '{latest_version[0]}'")
                continue
            logging.debug(f"no update found for helm chart '{repo_charts[0]}'. "
                          f"current version in ansible helm task is '{current_chart_version}'")
    return chart_updates


def handle_gitlab(chart_updates: List[dict],
                  gitlab_url: str,
                  gitlab_token: str,
                  project_id: int,
                  search_dir: str,
                  assignees: List[str] = [],
                  remove_source_branch: bool = False,
                  squash: bool = False,
                  automerge: bool = False,
                  merge_major: bool = False,
                  labels: List[str] = [],
                  verify_ssl: bool = False) -> List[dict]:
    """handle_gitlab handle gitlab workflow

    Args:
        chart_updates (list): list of dict with following keys:
                              chart_name: name of chart
                              old_version: current version of chart from ArgoCD manifest
                              new_version: newest available Helm chart version
                              yaml_path: path to ArgoCD manifest
                              mr_link: url to merge request
        gitlab_url (str): url to Gitlab
        gitlab_token (str): The user private token
        project_id (int): Gitlab project id
        search_dir (str): path to directory to search
        assignees (List[str], optional): list of strings with assignees. Defaults to [].
        remove_source_branch (bool, optional): remove brunch after merge. Defaults to False.
        squash (bool, optional): squash commits after merge. Defaults to False.
        automerge (bool, optional): merge request automatically. Defaults to False.
        merge_major (bool, optional): merge also major updates. Defaults to False.
        labels (List[str], optional): list of labels to set. Defaults to [].
        verify_ssl (bool, optional): check SSL certificate. Defaults to False.

    Raises:
        urllib3.exceptions.HTTPError: unable to connect to Gitlab
        urllib3.exceptions.ResponseError: unable to get assignees
        urllib3.exceptions.ResponseError: unable to get Gitlab project

    Returns:
        List[dict]: list of dict with following keys:
                    chart_name: name of chart
                    old_version: current version of chart from ArgoCD manifest
                    new_version: newest available Helm chart version
                    yaml_path: path to ArgoCD manifest
                    mr_link: url to merge request
    """
    try:
        conn = gitlab.Gitlab(url=gitlab_url,
                             private_token=gitlab_token,
                             ssl_verify=verify_ssl)
    except Exception as e:
        raise ConnectionError(f"unable to connect to gitlab. {str(e)}")

    try:
        if assignees:
            assignee_ids = get_assignee_ids(conn=conn,
                                            assignees=assignees)
    except Exception as e:
        raise urllib3.exceptions.ResponseError(f"unable to get assignees. {str(e)}")

    try:
        project = get_project(conn=conn,
                              project_id=project_id)
    except Exception as e:
        raise urllib3.exceptions.ResponseError(f"cannot get Gitlab project. {str(e)}")

    # the yaml path in the search_dir does not correspond to the path in the Gitlab repo
    # exmple:
    #  - search_dir: $CI_PROJECT_DIR
    #  - local_file_path: $CI_PROJECT_DIR/tasks/gitlab.yaml
    #  - gitlab_file_path: tasks/gitlab.yaml
    len_base = len(search_dir.rstrip("/"))
    for chart_update in chart_updates:
        local_file_path = str(chart_update['yaml_path'])
        gitlab_file_path = str(chart_update['yaml_path'])[len_base:]

        mr = None
        try:
            mr = update_project(project=project,
                                local_file_path=local_file_path,
                                gitlab_file_path=gitlab_file_path,
                                chart_name=chart_update['chart_name'],
                                old_version=chart_update['old_version'],
                                new_version=chart_update['new_version'],
                                remove_source_branch=remove_source_branch,
                                squash=squash,
                                automerge=automerge,
                                merge_major=merge_major,
                                assignee_ids=assignee_ids,
                                labels=labels)
        except Exception as e:
            logging.error(f"cannot update chart '{chart_update['chart_name']}' ('{gitlab_file_path}'). {e}")
        finally:
            if mr:
                chart_update['mr_link'] = mr.web_url

    return chart_updates


def get_assignee_ids(conn: Gitlab, assignees: List[str]) -> List[int]:
    """search assignees with name and get their id

    Args:
        conn (gitlab.Gitlab): GitLab server connection object
        assignees (List[str]): list of assignees with their names

    Raises:
        TypeError: parameter 'conn' is not of type 'gitlab.Gitlab'
        ConnectionError: unable to get assignees

    Returns:
        List[int]: list of assignees with their id's
    """
    if not isinstance(conn, gitlab.Gitlab):
        raise TypeError(f"parameter 'conn' must be of type 'gitlab.Gitlab', got '{type(conn)}'")

    assignee_ids = []
    for assignee in assignees:
        try:
            assignee = conn.users.list(search=assignee)
            if not assignee:
                logging.warning(f"id of '{assignee}' not found")
                continue
            assignee_ids.append(assignee[0].id)
        except GitlabGetError as e:
            logging.error(f"cannot get id of assignee '{assignee}'")
        except Exception as e:
            raise ConnectionError(f"unable to get assignees. {str(e)}")

    return assignee_ids


def get_project(conn: Gitlab, project_id: int) -> Project:
    """get Gitlab project as object

    Args:
        conn (gitlab.Gitlab): Gitlab server connection object
        project_id (int): project id

    Raises:
        TypeError: parameter 'conn' is not of type 'gitlab.Gitlab'
        GitlabGetError: project not found
        ConnectionError: cannot connect to Gitlab project

    Returns:
        gitlab.v4.objects.Project: Gitlab project object
    """

    if not isinstance(conn, gitlab.Gitlab):
        raise TypeError(f"parameter 'conn' must be of type 'gitlab.Gitlab', got '{type(conn)}'")

    try:
        project = conn.projects.get(project_id)
    except GitlabGetError as e:
        raise GitlabGetError(f"Project '{project_id}' not found. {e.error_message}")
    except Exception as e:
        raise ConnectionError(f"Unable to get Gitlab project. {str(e)}")

    return project


def update_project(project: Project,
                   local_file_path: str,
                   gitlab_file_path: str,
                   chart_name: str,
                   old_version: str,
                   new_version: str,
                   remove_source_branch: bool = False,
                   squash: bool = False,
                   automerge: bool = False,
                   merge_major: bool = False,
                   assignee_ids: List[int] = [],
                   labels: List[str] = []) -> ProjectMergeRequest:
    """Main function for handling branches, merge requests and version in file.

    - create/update a branch
    - create/update a merge request
    - replace the version in a file and updates the content to a Gitlab repo

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        local_file_path (str): path to the local file
        gitlab_file_path (str): path to file on Gitlab
        chart_name (str): name of chart repository
        old_version (str): current version of chart
        new_version (str): new version of chart
        remove_source_branch (bool, optional):. remove brunch after merge. Defaults to 'False'.
        squash (bool, optional):. squash commits after merge. Defaults to 'False'.
        automerge (bool, optional):. merge request automatically
        merge_major (bool, optional):. merge also major updates
        assignee_ids (List[int], optional): list of assignee id's to assign mr. Defaults to [].
        labels (List[str], optional): list of labels to set. Defaults to [].

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        LookupError: branch could not be created
        GitlabUpdateError: unable to update merge request
        GitlabCreateError: unable to create branch
        GitlabCreateError: unable to create merge request
        GitlabUploadError: unable to upload new file content

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: Gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    mergerequest_title = templates.merge_request_title.format(CHART_NAME=chart_name,
                                                              NEW_VERSION=new_version)

    try:
        merge_request = eval_merge_requests(project=project,
                                            title=mergerequest_title,
                                            chart_name=chart_name)
    except Exception as e:
        raise LookupError(f"unable check existing merge requests. {str(e)}")

    if merge_request.closed:
        return

    if merge_request.exists:
        pass # go on, maybe a file update is needed

    is_major = (semver.VersionInfo.parse(new_version.lstrip("v")).major >
                semver.VersionInfo.parse(old_version.lstrip("v")).major)

    if not automerge:
        config = "🚦 **Automerge**: Disabled by config. Please merge this manually once you are satisfied.\n\n"

    if automerge and is_major and merge_major:
        config = "🚦 **Automerge**: Enabled by config. Merge request will merge automatically.\n\n"

    if automerge and is_major and not merge_major:
        config = ("🚦 **Automerge**: Enabled by config, but disabled for major updates. "
                  "Please merge this manually once you are satisfied.\n\n")

    config += "🔕 **Ignore**: Close this MR and you won't be reminded about this update again."

    description = templates.description.format(NAME=chart_name,
                                               OLD_VERSION=old_version,
                                               NEW_VERSION=new_version,
                                               CONFIG=config)
    branch_name = templates.branch_name.format(CHART_NAME=chart_name)

    mr = None
    if merge_request.update:
        try:
            mr = get_merge_request_by_title(project=project,
                                            title=pattern.mr_title.format(CHART_NAME=chart_name),
                                            state="opened",
                                            sort="desc")
            if not mr:
                raise LookupError(f"merge request '{chart_name}' not found!")

            mr = mr[0]  # get newest merge request
            if labels:
                mr.labels = labels
            mr.title = mergerequest_title
            mr.description = description
            if remove_source_branch is not None:
                mr.remove_source_branch = str(remove_source_branch).lower() == "true"
            if squash is not None:
                mr.squash = str(squash).lower() == "true"
            mr.save()
        except Exception as e:
            raise GitlabUpdateError(f"cannot update merge request. {str(e)}")

    if merge_request.missing:
        try:
            create_branch(project=project,
                          branch_name=branch_name)
        except GitlabCreateError as e:
           logging.debug(f"cannot create branch '{branch_name}'. {str(e.error_message)}")
        except Exception as e:
            raise GitlabCreateError(f"cannot create branch '{branch_name}'. {str(e)}")

        try:
            mr = create_merge_request(project=project,
                                      branch_name=branch_name,
                                      description=description,
                                      title=mergerequest_title,
                                      remove_source_branch=remove_source_branch,
                                      squash=squash,
                                      assignee_ids=assignee_ids,
                                      labels=labels)
        except Exception as e:
            raise GitlabCreateError(f"unable to create merge request. {str(e)}")

    try:
        old_chart_version = re.compile(pattern=pattern.target_revision.format(VERSION=old_version),
                                       flags=re.IGNORECASE)
        new_chart_version = pattern.target_revision.format(VERSION=new_version)
        with open(file=local_file_path, mode="r+") as f:
            old_content = f.read()
            new_content = re.sub(pattern=old_chart_version,
                                 repl=new_chart_version,
                                 string=old_content)

            update_file(
                project=project,
                branch_name=branch_name,
                commit_msg=mergerequest_title,
                content=new_content,
                path_to_file=gitlab_file_path)
    except Exception as e:
        raise GitlabUploadError(f"unable to upload file. {str(e)}")

    try:
        if automerge:
            mr.merge(merge_when_pipeline_succeeds=True)
    except GitlabAuthenticationError as e:
        raise GitlabAuthenticationError(
                "Authentication not set correctly. 'Arginator' User must have the role 'Maintainer'")
    except Exception as e:
        raise Exception(f"cannot merge MR. {e}")

    return mr


def get_merge_request_by_title(project: Project,
                               title: str,
                               state: str = "all",
                               sort: str = "desc") -> List[ProjectMergeRequest]:
    """return list merge request by matching title (can be regex pattern)

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): name of chart. Can be regex pattern
        state (str, optional): state of merge requests. Must be one of
                               'all', 'merged', 'opened' or 'closed' Default to 'all'.
        state (str, optional): sort order of merge requests. 'asc' or 'desc'. Default to "desc.

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        TypeError: parameter 'state' is not 'all', 'merged', 'opened' or 'closed'
        TypeError: parameter 'sort' is not 'asc' or 'desc'

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: list of Gitlab merge request objects
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    if state not in ['all', 'merged', 'opened', 'closed']:
        raise TypeError("parameter 'state' must be 'all', 'merged', 'opened' or 'closed'")

    if sort not in ['asc', 'desc']:
        raise TypeError("parameter 'sort' must be 'asc' or 'desc'")

    mrs = project.mergerequests.list(order_by='updated_at',
                                     state=state,
                                     sort=sort)
    mr_title = re.compile(pattern=title,
                          flags=re.IGNORECASE)
    founds = []
    for mr in mrs:
        if mr_title.match(mr.title):
            founds.append(mr)

    return founds


def create_branch(project: Project,
                  branch_name: str) -> ProjectBranch:
    """create a branch on gitlab

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        branch_name (str): name of branch
    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'

    Returns:
        gitlab.v4.objects.ProjectBranch: Gitlab branch object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    branch = project.branches.create(
        {
            'branch': branch_name,
            'ref': 'master',
        }
    )

    logging.info(f"successfully created branch '{branch_name}'")

    return branch


def eval_merge_requests(project: Project,
                        title: str,
                        chart_name: str) -> namedtuple:
    """evaluate existing mergere request

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): title of merge request to search
        chart_name (str): name of chart

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'

    Returns:
        namedtuple: Status(closed=bool, exists=bool, update=bool, missing=bool)
                    closed: mr with same version exists and its status is closed
                    exists: mr with same version exists and its status is opened
                    update: mr status is opend but mr has other version
                    missing: none of the above conditions apply
                    Only one of the above status can be true
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    mr_title = re.compile(pattern=pattern.mr_title.format(CHART_NAME=chart_name),
                          flags=re.IGNORECASE)
    Status = namedtuple("Status", ['closed', 'exists', 'update', 'missing'])

    mrs = project.mergerequests.list(order_by='updated_at')
    for mr in mrs:
        if not mr_title.match(mr.title):
            continue

        if mr.state == "closed" and mr.title == title:
            logging.debug(f"merge request '{title}' was closed")
            return Status(closed=True, exists=False, update=False, missing=False)

        if mr.state == "opened" and mr.title == title:
            logging.debug(f"merge request '{title}' already exists")
            return Status(closed=False, exists=True, update=False, missing=False)

        if mr.state == "opened":
            return Status(closed=False, exists=False, update=True, missing=False)

    return Status(closed=False, exists=False, update=False, missing=True)


def create_merge_request(project: Project,
                         title: str,
                         branch_name: str,
                         description: str = None,
                         remove_source_branch: bool = False,
                         squash: bool = False,
                         assignee_ids: List[int] = [],
                         labels: List[str] = []) -> ProjectMergeRequest:
    """create merge request on a Gitlab project

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): title of branch
        branch_name (str, optional): name of branch. Defaults to 'master'.
        description (str, optional): description of merge request
        remove_source_branch (str, optional):. remove brunch after merge. Defaults to 'False'.
        squash (str, optional):. squash commits after merge. Defaults to 'False'.
        assignee_ids (List[int], optional): assign merge request to persons. Defaults to 'None'.
        labels (List[str]): labels to set

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        TypeError: parameter 'assignee_ids' must be a list of int
        TypeError: parameter 'labels' must be a list of strings
        LookupError: branch does not exist

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: Gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    if assignee_ids and not all(isinstance(a, int) for a in assignee_ids):
        raise TypeError("parameter 'assignee_ids' must be a list of int")

    if labels and not all(isinstance(l, str) for l in labels):
        raise TypeError(f"parameter 'labels' must be a list of strings")

    try:
        project.branches.get(branch_name)  # check if branch exists
    except GitlabGetError:
        raise LookupError(f"branch '{branch_name}' not found. to create a merge request, you need a branch!")
    except:
        raise

    mr = {
        'source_branch': branch_name,
        'target_branch': 'master',
        'title': title,
    }

    if description:
        mr['description'] = description

    if labels:
        mr['labels'] = labels

    if remove_source_branch is not None:
        mr['remove_source_branch'] = str(remove_source_branch).lower() == "true"

    if squash is not None:
        mr['squash'] = str(squash).lower() == "true"

    mr = project.mergerequests.create(mr)
    if assignee_ids:
        mr.todo()
        mr.assignee_ids = assignee_ids
        mr.save()

    logging.info(f"successfully created merge request '{title}'")

    return mr


def update_file(project: Project,
                commit_msg: str,
                content: str,
                path_to_file: str,
                branch_name: str = 'master') -> ProjectCommit:
    """update a file content on a Gitlab project

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        commit_msg (str): commit message
        content (str): file content as string
        path_to_file (str): path to file on the Gitlab project
        branch_name (str, optional): [description]. Defaults to 'master'.
    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    path_to_file = path_to_file.lstrip("/")

    commited_file = project.files.get(file_path=path_to_file,
                                      ref=branch_name)

    base64_message = commited_file.content
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    commit_conntent = message_bytes.decode('ascii')

    if content == commit_conntent:
        logging.debug("current commit is up to date")
        return

    payload = {
        "branch": branch_name,
        "commit_message": commit_msg,
        "actions": [
            {
                'action': 'update',
                'file_path': path_to_file,
                'content': content,
            }
        ]
    }

    commit = project.commits.create(payload)
    logging.info(f"successfully update file '{path_to_file}'")

    return commit


def send_slack(chart_updates: list, slack_token: str, slack_channel: str):
    """send_slack [summary]

    Args:
        chart_updates (list): [description]
        slack_token (str): [description]
        slack_channel (str): [description]
    """
    text = [f"The following chart update{'s are' if len(chart_updates) > 1 else ' is'} available:"]
    for chart in chart_updates:
        mr_link = chart.get('mr_link')
        text.append(templates.slack_notification.format(LINK_START=f"<{mr_link} | " if mr_link else "",
                                                        CHART_NAME=chart['chart_name'],
                                                        LINK_END=">" if mr_link else "",
                                                        OLD_VERSION=chart['old_version'],
                                                        NEW_VERSION=f"{chart['new_version']}" if mr_link else
                                                                        chart['new_version'])
        )
    text = '\n'.join(text)

    try:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(channel=slack_channel,
                                      text=text)
    except SlackApiError as e:
        raise


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"{str(e)}\n")
        sys.exit(1)

    try:
        setup_logger(loglevel=env_vars.loglevel)
    except Exception as e:
        logging.critical(f"cannot setup logger. {e}")
        sys.exit(1)

    try:
        argo_helm_charts = process_yaml(search_dir=env_vars.search_dir)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        chart_updates = process_argo_helm_charts(argo_helm_charts=argo_helm_charts)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    if env_vars.enable_mergerequests and chart_updates:
        try:
            handle_gitlab(chart_updates=chart_updates,
                          gitlab_url=env_vars.gitlab_url,
                          gitlab_token=env_vars.gitlab_token,
                          project_id=env_vars.project_id,
                          search_dir=env_vars.search_dir,
                          assignees=env_vars.assignees,
                          remove_source_branch=env_vars.remove_source_branch,
                          squash=env_vars.squash,
                          automerge=env_vars.automerge,
                          merge_major=env_vars.merge_major,
                          labels=env_vars.labels,
                          verify_ssl=env_vars.verify_ssl,
            )
        except Exception as e:
            logging.error(f"cannot create Gitlab merge request. {str(e)}")

    if env_vars.slack_token and chart_updates:
        try:
            send_slack(chart_updates=chart_updates,
                       slack_token=env_vars.slack_token,
                       slack_channel=env_vars.slack_channel)
        except Exception as e:
            logging.error(f"cannot send Slack message. {str(e)}")

    logging.info("{AMOUNT} chart update{PLURAL} found".format(
        AMOUNT=f"{len(chart_updates)}" if chart_updates else "no",
        PLURAL="s" if len(chart_updates) != 1 else "")
    )

    sys.exit(1 if logging.error.counter or logging.critical.counter else 0)

if __name__ == "__main__":
    main()
