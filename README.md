# Arginator

![Docker Image Version (latest semver)](https://img.shields.io/docker/v/containeroo/arginator?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/containeroo/arginator?style=flat-square)
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/containeroo/arginator/latest?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/containeroo/arginator?style=flat-square)
![Twitter Follow](https://img.shields.io/twitter/follow/containeroo?style=social)

## Introduction

arginator scans a Gitlab repo for ArgoCD Application yaml files.
It then checks if there is an update to any of the defined Helm charts available. If configured, it creates a branch and merge request and/or send out a Slack notification.
arginator is built to run in a CI environment (e.g. GitLab CI).

## Requirements

- Kubernetes Cluster
- ArgoCD
- GitLab
- Slack App (optional)

## Configration

arginator takes the following environment variables:

| Variable                                 | Description                                                                                                          | Example                                                |
| :--------------------------------------- | :------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------- |
| `ARGINATOR_ROOT_DIR`            | Directory to scan (defaults to `CI_PROJECT_DIR`)                                                                     | `ansible/`                                             |
| `ARGINATOR_ENABLE_PRERELEASES`          | Enable pre-release processing (defaults to `false`)                                                                  | `true` or `false`                                      |
| `ARGINATOR_VERIFY_SSL`                  | Verify ssl certificate (defaults to `true`)                                                                          | `true` or `false`                                      |
| `ARGINATOR_LOGLEVEL`                    | Set loglevel (defaults to `info`)                                                                                    | one of `critical`, `error`, `warning`, `info`, `debug` |
| `ARGINATOR_ENABLE_MERGEREQUESTS`        | Create for each chart update a merge request (defaults to `true`)                                                    | `true` or `false`                                      |
| `ARGINATOR_GITLAB_TOKEN`                | Gitlab access token (more detail see below)                                                                          | `12345678`                                             |
| `ARGINATOR_GITLAB_REMOVE_SOURCE_BRANCH` | Delete source branch when merge request is accepted (defaults to `true`)                                             | `true` or `false`                                      |
| `ARGINATOR_GITLAB_SQUASH_COMMITS`       | Squash commits when merge request is accepted (defaults to `false`)                                                  | `true` or `false`                                      |
| `ARGINATOR_GITLAB_AUTOMERGE`            | Accept merge request and close it (defaults to`false`)                                                               | `true` or `false`                                      |
| `ARGINATOR_GITLAB_MERGE_MAJOR`          | Automerge also major updates (defaults to`false`)                                                                    | `true` or `false`                                      |
| `ARGINATOR_GITLAB_ASSIGNEES`            | List of name of assignees, separate by a comma                                                                       | `user1,user2`                                          |
| `ARGINATOR_GITLAB_LABELS`               | List of labels to set on a merge request, separate by a comma. set it to "" for no labels (defaults to `arginator`) | `helm,update,k8s`                                      |
| `ARGINATOR_SLACK_API_TOKEN`             | Slack API Token                                                                                                      | `xorb-abc-def`                                         |
| `ARGINATOR_SLACK_CHANNEL`               | Slack channel to send message to                                                                                     | `#kubernetes`                                          |

*GITLAB_TOKEN*
*Add a user as member with role developer to a project and use his token.*

### Slack App

To receive Slack notifications you have to create a Slack App. Please refer to [this guide](https://github.com/slackapi/python-slackclient/blob/master/tutorial/01-creating-the-slack-app.md).

## Usage

### GitLab

If you want to use arginator in a GitLab CI / CD job, you can use the follwing `.gitlab-ci.yml` as an example:

```yaml
image:
  name: containeroo/arginator:latest
  entrypoint: [""]

stages:
  - arginator

arginator:
  stage: arginator
  only:
    - schedules
  script: python /app/arginator.py
```

In order to set the configration environment variables, go to your project (repository) containing the ArgoCD manifests.  
Go to `Settings` -> `CI / CD` -> `Variabels` -> `Expand`.

After you have set all variables you can create a pipeline schedule. This ensures your job runs regularly.
