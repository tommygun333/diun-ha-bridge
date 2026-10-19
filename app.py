import json
import os
import queue
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote

import paho.mqtt.client as mqtt
import requests


# ===========================================================================
# Configuration
# ===========================================================================

MQTT_HOST = os.getenv("MQTT_HOST", "192.168.1.10")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")

DISCOVERY_PREFIX = os.getenv("HA_DISCOVERY_PREFIX", "homeassistant")
TOPIC_PREFIX = os.getenv("TOPIC_PREFIX", "diun-ha")
DIUN_EVENT_TOPIC = os.getenv("DIUN_EVENT_TOPIC", "diun/events")

UPDATER_TOPIC_PREFIX = os.getenv(
    "UPDATER_TOPIC_PREFIX",
    "homelab-updater",
).strip("/")

HOSTS_FILE = os.getenv("HOSTS_FILE", "/config/hosts.json")

LOCAL_SCAN_INTERVAL = int(os.getenv("LOCAL_SCAN_INTERVAL", "300"))
REMOTE_SCAN_INTERVAL = int(os.getenv("REMOTE_SCAN_INTERVAL", "86400"))

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
SKOPEO_TIMEOUT = int(os.getenv("SKOPEO_TIMEOUT", "60"))

# Optional. Not required for one or two public GitHub repositories,
# but can be supplied later if API rate limiting ever becomes an issue.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# ===========================================================================
# Runtime state
# ===========================================================================

event_queue = queue.Queue()

updater_event_queue = queue.Queue()

# host -> {"action-name": capability metadata}
updater_capabilities = {}

# host -> bool
updater_online = {}

# host -> latest updater status payload
updater_status = {}

# HA update entities that have already been published.
# Used to change in_progress immediately without performing
# a full Docker/registry scan.
published_update_entities = {}

# canonical image -> skopeo metadata
remote_cache = {}

# Docker Hub repository -> {digest: set(tags)}
dockerhub_tag_cache = {}

# (repo, branch) -> Git commit SHA
git_revision_cache = {}

# Current HA-facing state used by summary sensor
latest_states = {}

session = requests.Session()


GENERIC_TAGS = {
    "latest",
    "stable",
    "main",
    "master",
    "develop",
    "development",
    "edge",
    "nightly",
    "daily",
}


# Huge repositories where tag-enrichment isn't worth crawling.
# Digest update detection still works normally.
TAG_ALIAS_SKIP_REPOS = {
    "docker.io/library/redis",
    "docker.io/library/postgres",
}


CUSTOM_STRATEGIES = {
    "base-image",
    "git-revision",
}


# ===========================================================================
# General helpers
# ===========================================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def slug(value):
    value = value.lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    return value.strip("_")


def short_digest(digest):
    if not digest:
        return "unknown"

    return str(digest).replace(
        "sha256:",
        "",
    )[:12]


def short_revision(revision):
    if not revision:
        return None

    return str(revision).strip()[:8]


def env_list_to_dict(env_list):
    result = {}

    for item in env_list or []:
        if "=" not in item:
            continue

        key, value = item.split(
            "=",
            1,
        )

        result[key] = value

    return result


def same_source(a, b):
    if not a or not b:
        return False

    def normalize(value):
        value = str(value).strip().rstrip("/")

        if value.endswith(".git"):
            value = value[:-4]

        return value.lower()

    return normalize(a) == normalize(b)


def container_display_name(container):
    names = container.get("Names") or []

    if names:
        return names[0].lstrip("/")

    return container.get("Id", "unknown")[:12]


def updater_command_topic(host_name):
    return (
        f"{UPDATER_TOPIC_PREFIX}/"
        f"{host_name}/command"
    )


def updater_action_supported(
    host_name,
    action,
):
    if not action:
        return False

    if not updater_online.get(
        host_name,
        False,
    ):
        return False

    capabilities = (
        updater_capabilities.get(
            host_name,
            {},
        )
    )

    return (
        action
        in capabilities
    )


def updater_action_running(
    host_name,
    action,
):
    if not action:
        return False

    status = (
        updater_status.get(
            host_name,
            {}
        )
    )

    return (
        status.get("state")
        == "running"
        and
        status.get("action")
        == action
    )


# ===========================================================================
# Docker image reference helpers
# ===========================================================================

def canonical_image(ref):
    ref = str(ref).strip()

    if ref.startswith("docker://"):
        ref = ref[9:]

    digest = None

    if "@" in ref:
        name, digest = ref.split(
            "@",
            1,
        )

    else:
        name = ref

        last = name.rsplit(
            "/",
            1,
        )[-1]

        if ":" not in last:
            name += ":latest"

    last_slash = name.rfind("/")
    last_colon = name.rfind(":")

    if last_colon > last_slash:
        repo = name[:last_colon]
        tag = name[last_colon:]

    else:
        repo = name
        tag = ""

    parts = repo.split("/")

    if len(parts) == 1:
        repo = (
            f"docker.io/library/{repo}"
        )

    elif (
        "." not in parts[0]
        and ":" not in parts[0]
        and parts[0] != "localhost"
    ):
        repo = (
            f"docker.io/{repo}"
        )

    result = repo + tag

    if digest:
        result += f"@{digest}"

    return result


def image_repository(ref):
    ref = canonical_image(ref)

    if "@" in ref:
        return ref.split(
            "@",
            1,
        )[0]

    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")

    if last_colon > last_slash:
        return ref[:last_colon]

    return ref


# ===========================================================================
# Version helpers
# ===========================================================================

def extract_version(labels):
    if not labels:
        return None

    preferred = [
        "org.opencontainers.image.version",
        "org.label-schema.version",
        "version",
    ]

    for key in preferred:
        value = labels.get(key)

        if value:
            return str(value).strip()

    build_version = labels.get(
        "build_version"
    )

    if build_version:
        match = re.search(
            r"version:\s*-\s*([^\s]+)",
            str(build_version),
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

        return str(
            build_version
        ).strip()

    return None


def semver_from_tag(tag):
    if not tag:
        return None

    match = re.fullmatch(
        r"v?(\d+)\.(\d+)\.(\d+)",
        str(tag).strip(),
    )

    if not match:
        return None

    return ".".join(
        match.groups()
    )


def version_from_image_tag(image):
    image = canonical_image(
        image
    )

    if "@" in image:
        return None

    last_slash = image.rfind("/")
    last_colon = image.rfind(":")

    if last_colon <= last_slash:
        return None

    tag = image[
        last_colon + 1:
    ]

    return semver_from_tag(tag)


def parse_numeric_version(value):
    if not value:
        return None

    match = re.match(
        r"^v?(\d+(?:\.\d+)+)",
        str(value).strip(),
    )

    if not match:
        return None

    return tuple(
        int(part)
        for part
        in match.group(1).split(".")
    )


def parse_git_describe(value):
    if not value:
        return None

    match = re.fullmatch(
        r"v?(\d+(?:\.\d+)+)-(\d+)-g([0-9a-fA-F]+)",
        str(value).strip(),
    )

    if not match:
        return None

    return {
        "version": tuple(
            int(part)
            for part
            in match.group(1).split(".")
        ),

        "commits": int(
            match.group(2)
        ),

        "revision": (
            match.group(3)
        ),
    }


def compare_numeric_tuples(a, b):
    width = max(
        len(a),
        len(b),
    )

    a = (
        a
        + (0,) * (width - len(a))
    )

    b = (
        b
        + (0,) * (width - len(b))
    )

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def version_update_available(
    installed,
    available,
):
    if not installed or not available:
        return None

    installed = str(
        installed
    ).strip()

    available = str(
        available
    ).strip()

    if installed == available:
        return False

    installed_git = (
        parse_git_describe(
            installed
        )
    )

    available_numeric = (
        parse_numeric_version(
            available
        )
    )

    # Example:
    #
    # local:    v3.4.1-39-g96c2c06b
    # upstream: v3.4.1
    #
    # Local is already beyond that release.
    if (
        installed_git
        and available_numeric
    ):
        comparison = (
            compare_numeric_tuples(
                installed_git["version"],
                available_numeric,
            )
        )

        if comparison < 0:
            return True

        return False

    installed_numeric = (
        parse_numeric_version(
            installed
        )
    )

    if (
        installed_numeric
        and available_numeric
    ):
        return (
            compare_numeric_tuples(
                installed_numeric,
                available_numeric,
            )
            < 0
        )

    return None


# ===========================================================================
# Docker Hub digest -> version-tag resolution
# ===========================================================================

def dockerhub_repository(image):
    image = canonical_image(
        image
    )

    if not image.startswith(
        "docker.io/"
    ):
        return None

    repo = image[
        len("docker.io/"):
    ]

    if "@" in repo:
        repo = repo.split(
            "@",
            1,
        )[0]

    last_slash = repo.rfind("/")
    last_colon = repo.rfind(":")

    if last_colon > last_slash:
        repo = repo[:last_colon]

    return repo


def load_dockerhub_tags(image):
    repo = dockerhub_repository(
        image
    )

    if not repo:
        return {}

    if repo in dockerhub_tag_cache:
        return dockerhub_tag_cache[
            repo
        ]

    digest_tags = {}

    url = (
        f"https://hub.docker.com/v2/repositories/"
        f"{repo}/tags"
        f"?page_size=100"
        f"&ordering=last_updated"
    )

    pages = 0
    max_pages = 10

    while (
        url
        and pages < max_pages
    ):
        try:
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 403:
                print(
                    f"[tags] {repo}: "
                    f"Docker Hub stopped pagination "
                    f"after {pages} page(s); "
                    f"using collected tag data",
                    flush=True,
                )

                break

            response.raise_for_status()

            data = response.json()

        except requests.RequestException as exc:
            print(
                f"[tags] {repo}: "
                f"pagination stopped after "
                f"{pages} page(s): {exc}",
                flush=True,
            )

            break

        for item in data.get(
            "results",
            [],
        ):
            tag = item.get(
                "name"
            )

            if not tag:
                continue

            if (
                tag.startswith("sha256-")
                or tag.endswith(".sig")
                or tag.endswith(".att")
            ):
                continue

            digests = set()

            if item.get("digest"):
                digests.add(
                    item["digest"]
                )

            for platform in (
                item.get("images")
                or []
            ):
                digest = (
                    platform.get(
                        "digest"
                    )
                )

                if digest:
                    digests.add(
                        digest
                    )

            for digest in digests:
                digest_tags.setdefault(
                    digest,
                    set(),
                ).add(
                    tag
                )

        url = data.get(
            "next"
        )

        pages += 1

    dockerhub_tag_cache[
        repo
    ] = digest_tags

    return digest_tags


def version_from_dockerhub_digest(
    image,
    digest,
):
    if not digest:
        return None

    repo_full = image_repository(
        image
    )

    if (
        repo_full
        in TAG_ALIAS_SKIP_REPOS
    ):
        return None

    try:
        digest_tags = (
            load_dockerhub_tags(
                image
            )
        )

    except Exception as exc:
        print(
            f"[tags] {image}: "
            f"{exc}",
            flush=True,
        )

        return None

    tags = digest_tags.get(
        digest,
        set(),
    )

    versions = []

    for tag in tags:
        version = (
            semver_from_tag(
                tag
            )
        )

        if not version:
            continue

        parts = tuple(
            int(part)
            for part
            in version.split(".")
        )

        versions.append(
            (
                parts,
                version,
            )
        )

    if not versions:
        return None

    versions.sort(
        reverse=True
    )

    return versions[0][1]


# ===========================================================================
# Revision / pretty-version helpers
# ===========================================================================

def revision_version(info):
    labels = (
        info.get("labels")
        or {}
    )

    revision = labels.get(
        "org.opencontainers.image.revision"
    )

    if not revision:
        return None

    revision = str(
        revision
    ).strip()

    if not revision:
        return None

    return revision[:8]


def revision_display(
    revision,
    channel=None,
):
    short = short_revision(
        revision
    )

    if not short:
        return None

    if channel:
        channel = str(
            channel
        ).strip()

        if channel:
            return (
                f"{channel}@{short}"
            )

    return (
        f"rev-{short}"
    )


def resolve_pretty_version(info):
    # -----------------------------------------------------------------------
    # 1. Exact semantic version from the image tag itself.
    #
    # Example:
    #   image: app:1.2.3
    #
    # This is more trustworthy than inherited OCI labels.
    # -----------------------------------------------------------------------

    version = (
        version_from_image_tag(
            info["image"]
        )
    )

    if version:
        return version

    # -----------------------------------------------------------------------
    # 2. Docker Hub tag pointing at this exact digest.
    #
    # This handles images such as ollama/ollama:latest where the image
    # inherits an unrelated base-image OCI version label (Ubuntu 24.04),
    # while Docker Hub also has a real application-version tag pointing at
    # the exact same manifest digest.
    # -----------------------------------------------------------------------

    version = (
        version_from_dockerhub_digest(
            info["image"],
            info.get(
                "digest"
            ),
        )
    )

    if version:
        return version

    # -----------------------------------------------------------------------
    # 3. OCI/application version label.
    #
    # Useful when the publisher explicitly stamps its own version and there
    # is no better version available from the image tag/digest.
    # -----------------------------------------------------------------------

    version = info.get(
        "version"
    )

    if (
        version
        and str(version).lower()
        not in GENERIC_TAGS
    ):
        return str(
            version
        )

    # -----------------------------------------------------------------------
    # 4. Source revision fallback
    # -----------------------------------------------------------------------

    revision = (
        revision_version(
            info
        )
    )

    if revision:
        original = info.get(
            "version"
        )

        if (
            original
            and str(original).lower()
            in GENERIC_TAGS
        ):
            return (
                f"{original}@"
                f"{revision}"
            )

        return (
            f"rev-{revision}"
        )

    return None

# ===========================================================================
# GitHub revision lookup
# ===========================================================================

def github_branch_revision(
    repository,
    branch,
):
    """
    Return HEAD SHA for a public GitHub branch.

    repository:
        owner/repository

    branch:
        e.g. release, main
    """

    repository = str(
        repository
    ).strip()

    branch = str(
        branch
    ).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        repository,
    ):
        raise ValueError(
            f"Invalid GitHub repository: {repository}"
        )

    if not branch:
        raise ValueError(
            "Git branch is empty"
        )

    cache_key = (
        repository.lower(),
        branch,
    )

    if cache_key in git_revision_cache:
        return git_revision_cache[
            cache_key
        ]

    url = (
        f"https://api.github.com/repos/"
        f"{repository}/commits/"
        f"{quote(branch, safe='')}"
    )

    headers = {
        "Accept": (
            "application/vnd.github+json"
        ),

        "User-Agent": (
            "diun-ha-bridge"
        ),

        "X-GitHub-Api-Version": (
            "2022-11-28"
        ),
    }

    if GITHUB_TOKEN:
        headers[
            "Authorization"
        ] = (
            f"Bearer "
            f"{GITHUB_TOKEN}"
        )

    response = session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 403:
        remaining = response.headers.get(
            "X-RateLimit-Remaining"
        )

        reset = response.headers.get(
            "X-RateLimit-Reset"
        )

        raise RuntimeError(
            "GitHub API returned 403"
            f" (remaining={remaining},"
            f" reset={reset})"
        )

    response.raise_for_status()

    data = response.json()

    revision = data.get(
        "sha"
    )

    if not revision:
        raise RuntimeError(
            "GitHub response contained "
            "no commit SHA"
        )

    revision = str(
        revision
    ).strip()

    git_revision_cache[
        cache_key
    ] = revision

    return revision


# ===========================================================================
# Docker socket proxy
# ===========================================================================

def docker_get(
    endpoint,
    path,
):
    url = (
        endpoint.rstrip("/")
        + path
    )

    response = session.get(
        url,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()


def local_image_info(
    host,
    container,
):
    endpoint = host[
        "endpoint"
    ]

    cid = container[
        "Id"
    ]

    container_info = docker_get(
        endpoint,
        f"/containers/"
        f"{quote(cid, safe='')}"
        f"/json",
    )

    image_ref = (
        container_info
        .get("Config", {})
        .get("Image")

        or container.get(
            "Image"
        )
    )

    image_id = (
        container_info.get(
            "Image"
        )
    )

    image_info = docker_get(
        endpoint,
        f"/images/"
        f"{quote(image_id, safe='')}"
        f"/json",
    )

    image_labels = (
        image_info
        .get("Config", {})
        .get("Labels")
        or {}
    )

    container_labels = (
        container_info
        .get("Config", {})
        .get("Labels")
        or {}
    )

    labels = dict(
        image_labels
    )

    labels.update(
        container_labels
    )

    repo_digests = (
        image_info.get(
            "RepoDigests"
        )
        or []
    )

    wanted_repo = (
        image_repository(
            image_ref
        )
    )

    digest = None

    for item in repo_digests:
        if "@" not in item:
            continue

        repo, candidate = (
            item.rsplit(
                "@",
                1,
            )
        )

        if (
            image_repository(
                repo
            )
            == wanted_repo
        ):
            digest = candidate
            break

    if (
        digest is None
        and repo_digests
    ):
        digest = (
            repo_digests[0]
            .rsplit("@", 1)[-1]
        )

    name = (
        container_info
        .get("Name", "")
        .lstrip("/")
    )

    image_env = (
        env_list_to_dict(
            image_info
            .get("Config", {})
            .get("Env")
            or []
        )
    )

    return {
        "container": name,

        "container_id": cid,

        "image": canonical_image(
            image_ref
        ),

        "image_id": image_id,

        "digest": digest,

        "labels": labels,

        "image_labels": (
            image_labels
        ),

        "container_labels": (
            container_labels
        ),

        "env": image_env,

        "version": extract_version(
            labels
        ),

        "state": (
            container_info
            .get("State", {})
            .get(
                "Status",
                "unknown",
            )
        ),
    }


# ===========================================================================
# Remote registry inspection
# ===========================================================================

def remote_image_info(image):
    image = canonical_image(
        image
    )

    command = [
        "skopeo",
        "inspect",
        "--no-tags",
        "--retry-times",
        "1",
        f"docker://{image}",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=SKOPEO_TIMEOUT,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
        )

    data = json.loads(
        result.stdout
    )

    labels = (
        data.get("Labels")
        or {}
    )

    return {
        "image": image,

        "digest": (
            data.get("Digest")
        ),

        "labels": labels,

        "env": env_list_to_dict(
            data.get("Env")
            or []
        ),

        "version": extract_version(
            labels
        ),

        "created": (
            data.get("Created")
        ),

        "architecture": (
            data.get(
                "Architecture"
            )
        ),

        "os": (
            data.get("Os")
        ),
    }


# ===========================================================================
# Installed/latest display logic
# ===========================================================================

def choose_display_versions(
    local,
    remote,
):
    local_version = (
        resolve_pretty_version(
            local
        )
    )

    remote_version = (
        resolve_pretty_version(
            remote
        )
    )

    # -----------------------------------------------------------------------
    # Custom locally-built image / source build
    # -----------------------------------------------------------------------

    if local.get(
        "custom_image"
    ):
        update_available = bool(
            local.get(
                "custom_update_available"
            )
        )

        built_from_digest = (
            local.get(
                "base_digest"
            )
        )

        remote_digest = (
            remote.get(
                "digest"
            )
        )

        # HA derives update state from installed_version != latest_version.
        #
        # If OUR comparator says no update, force those two displayed values
        # to be identical. Real upstream information remains in attributes.
        if not update_available:
            current_display = (
                local_version
                or remote_version
                or (
                    f"digest-"
                    f"{short_digest(built_from_digest)}"
                )
            )

            return (
                current_display,
                current_display,
            )

        if (
            local_version
            and remote_version
        ):
            if (
                local_version
                != remote_version
            ):
                return (
                    local_version,
                    remote_version,
                )

            if (
                built_from_digest
                and remote_digest
            ):
                return (
                    f"{local_version}+"
                    f"{short_digest(built_from_digest)}",

                    f"{remote_version}+"
                    f"{short_digest(remote_digest)}",
                )

            return (
                local_version,
                remote_version,
            )

        if (
            local_version
            or remote_version
        ):
            return (
                local_version
                or (
                    f"digest-"
                    f"{short_digest(built_from_digest)}"
                ),

                remote_version
                or (
                    f"digest-"
                    f"{short_digest(remote_digest)}"
                ),
            )

        return (
            f"digest-"
            f"{short_digest(built_from_digest)}",

            f"digest-"
            f"{short_digest(remote_digest)}",
        )

    # -----------------------------------------------------------------------
    # Normal registry-backed image
    # -----------------------------------------------------------------------

    local_digest = (
        local.get("digest")
    )

    remote_digest = (
        remote.get("digest")
    )

    if (
        local_digest
        and remote_digest
        and local_digest
        == remote_digest
    ):
        version = (
            local_version
            or remote_version
        )

        if version:
            return (
                version,
                version,
            )

        digest_label = (
            f"digest-"
            f"{short_digest(local_digest)}"
        )

        return (
            digest_label,
            digest_label,
        )

    if (
        local_version
        and remote_version
        and local_version
        != remote_version
    ):
        return (
            local_version,
            remote_version,
        )

    if (
        local_version
        and remote_version
    ):
        return (
            f"{local_version}+"
            f"{short_digest(local_digest)}",

            f"{remote_version}+"
            f"{short_digest(remote_digest)}",
        )

    if (
        local_version
        or remote_version
    ):
        return (
            local_version
            or (
                f"digest-"
                f"{short_digest(local_digest)}"
            ),

            remote_version
            or (
                f"digest-"
                f"{short_digest(remote_digest)}"
            ),
        )

    return (
        f"digest-"
        f"{short_digest(local_digest)}",

        f"digest-"
        f"{short_digest(remote_digest)}",
    )


# ===========================================================================
# MQTT
# ===========================================================================

def mqtt_publish(
    topic,
    payload,
    retain=True,
):
    if not isinstance(
        payload,
        str,
    ):
        payload = json.dumps(
            payload,
            separators=(",", ":"),
        )

    client.publish(
        topic,
        payload,
        qos=1,
        retain=retain,
    )


# ===========================================================================
# Home Assistant MQTT Discovery
# ===========================================================================

def publish_entity(
    host_name,
    local,
    remote,
    error=None,
):
    host_slug = slug(
        host_name
    )

    container_slug = slug(
        local["container"]
    )

    unique_id = (
        f"diun_"
        f"{host_slug}_"
        f"{container_slug}"
    )

    state_topic = (
        f"{TOPIC_PREFIX}/"
        f"{host_slug}/"
        f"{container_slug}/"
        f"state"
    )

    attr_topic = (
        f"{TOPIC_PREFIX}/"
        f"{host_slug}/"
        f"{container_slug}/"
        f"attributes"
    )

    discovery_topic = (
        f"{DISCOVERY_PREFIX}/"
        f"update/"
        f"{unique_id}/"
        f"config"
    )

    installed, latest = (
        choose_display_versions(
            local,
            remote,
        )
    )

    local_digest = (
        local.get(
            "digest"
        )
    )

    remote_digest = (
        remote.get(
            "digest"
        )
    )

    if (
        "custom_update_available"
        in local
    ):
        update_available = bool(
            local[
                "custom_update_available"
            ]
        )

    else:
        update_available = bool(
            local_digest
            and remote_digest
            and local_digest
            != remote_digest
        )

    update_action = (
        local
        .get("labels", {})
        .get(
            "homelab.update.action"
        )
    )

    if update_action:
        update_action = str(
            update_action
        ).strip()

    if not update_action:
        update_action = None

    installable = (
        updater_action_supported(
            host_name,
            update_action,
        )
    )

    in_progress = (
        updater_action_running(
            host_name,
            update_action,
        )
    )

    title = (
        remote
        .get("labels", {})
        .get(
            "homelab.update.name"
        )

        or local
        .get("labels", {})
        .get(
            "org.opencontainers.image.title"
        )

        or local[
            "container"
        ]
    )

    release_url = (
        remote
        .get("labels", {})
        .get(
            "org.opencontainers.image.url"
        )

        or remote
        .get("labels", {})
        .get(
            "org.opencontainers.image.source"
        )    )

    display_name = (
        local
        .get("labels", {})
        .get(
            "homelab.update.name"
        )

        or local[
            "container"
        ]
    )

    config = {
        "name": (
            display_name
        ),

        "unique_id": (
            unique_id
        ),

        "default_entity_id": (
            f"update.docker_"
            f"{host_slug}_"
            f"{container_slug}"
        ),

        "state_topic": (
            state_topic
        ),

        "json_attributes_topic": (
            attr_topic
        ),

        "qos": 1,

        "device": {
            "identifiers": [
                f"docker_host_"
                f"{host_slug}"
            ],

            "name": (
                f"Docker - "
                f"{host_name}"
            ),

            "manufacturer": (
                "Diun HA Bridge"
            ),

            "model": (
                "Docker Host"
            ),
        },
    }

    if installable:
        config[
            "command_topic"
        ] = updater_command_topic(
            host_name
        )

        config[
            "payload_install"
        ] = json.dumps(
            {
                "action": (
                    update_action
                )
            },
            separators=(",", ":"),
        )

    mqtt_publish(
        discovery_topic,
        config,
    )

    state = {
        "installed_version": (
            installed
        ),

        "latest_version": (
            latest
        ),

        "title": (
            title
        ),

        "in_progress": (
            in_progress
        ),
    }

    if release_url:
        state[
            "release_url"
        ] = release_url

    mqtt_publish(
        state_topic,
        state,
    )

    attrs = {
        "host": (
            host_name
        ),

        "update_action": (
            update_action
        ),

        "updater_online": (
            updater_online.get(
                host_name,
                False,
            )
        ),

        "updater_installable": (
            installable
        ),

        "container": (
            local["container"]
        ),

        "container_state": (
            local["state"]
        ),

        "image": (
            local["image"]
        ),

        "update_strategy": (
            local.get(
                "update_strategy"
            )
        ),

        "installed_version_raw": (
            local.get(
                "source_version_raw",
                local.get(
                    "version"
                ),
            )
        ),

        "available_version_raw": (
            remote.get(
                "source_version_raw",
                remote.get(
                    "version"
                ),
            )
        ),

        "installed_version_resolved": (
            installed
        ),

        "available_version_resolved": (
            latest
        ),

        "installed_digest": (
            local_digest
        ),

        "available_digest": (
            remote_digest
        ),

        "update_available": (
            update_available
        ),

        "update_available_by_digest": bool(
            local_digest
            and remote_digest
            and local_digest
            != remote_digest
        ),

        "remote_created": (
            remote.get(
                "created"
            )
        ),

        "remote_architecture": (
            remote.get(
                "architecture"
            )
        ),

        "remote_os": (
            remote.get(
                "os"
            )
        ),

        "custom_image": (
            local.get(
                "custom_image",
                False,
            )
        ),

        "base_image": (
            local.get(
                "base_image"
            )
        ),

        "base_digest": (
            local.get(
                "base_digest"
            )
        ),

        "comparison_method": (
            local.get(
                "comparison_method",
                "image-digest",
            )
        ),

        "version_env": (
            local.get(
                "version_env"
            )
        ),

        "version_mode": (
            local.get(
                "version_mode"
            )
        ),

        "upstream_version": (
            local.get(
                "upstream_version"
            )
        ),

        "installed_base_revision": (
            local.get(
                "installed_base_revision"
            )
        ),

        "available_base_revision": (
            local.get(
                "available_base_revision"
            )
        ),

        # git-revision strategy
        "git_repository": (
            local.get(
                "git_repository"
            )
        ),

        "git_branch": (
            local.get(
                "git_branch"
            )
        ),

        "installed_source_revision": (
            local.get(
                "installed_source_revision"
            )
        ),

        "available_source_revision": (
            local.get(
                "available_source_revision"
            )
        ),

        "last_checked": (
            now_iso()
        ),
    }

    if error:
        attrs[
            "error"
        ] = error

    mqtt_publish(
        attr_topic,
        attrs,
    )

    published_update_entities[
        unique_id
    ] = {
        "host": (
            host_name
        ),

        "action": (
            update_action
        ),

        "state_topic": (
            state_topic
        ),

        "state": (
            dict(state)
        ),
    }

    latest_states[
        unique_id
    ] = {
        "host": (
            host_name
        ),

        "container": (
            local["container"]
        ),

        "installed": (
            installed
        ),

        "latest": (
            latest
        ),

        "update_available": (
            update_available
        ),

        "image": (
            local["image"]
        ),

        "custom_image": (
            local.get(
                "custom_image",
                False,
            )
        ),
    }


def publish_summary():
    updates = [
        value
        for value
        in latest_states.values()
        if value.get(
            "update_available"
        )
    ]

    config_topic = (
        f"{DISCOVERY_PREFIX}/"
        f"sensor/"
        f"diun_ha_updates/"
        f"config"
    )

    state_topic = (
        f"{TOPIC_PREFIX}/"
        f"summary/state"
    )

    attr_topic = (
        f"{TOPIC_PREFIX}/"
        f"summary/attributes"
    )

    mqtt_publish(
        config_topic,
        {
            "name": (
                "Docker Updates"
            ),

            "unique_id": (
                "diun_ha_updates"
            ),

            "default_entity_id": (
                "sensor.docker_updates"
            ),

            "state_topic": (
                state_topic
            ),

            "json_attributes_topic": (
                attr_topic
            ),

            "icon": (
                "mdi:package-up"
            ),

            "qos": 1,
        },
    )

    mqtt_publish(
        state_topic,
        str(
            len(updates)
        ),
    )

    mqtt_publish(
        attr_topic,
        {
            "updates": (
                updates
            ),

            "total_containers": (
                len(
                    latest_states
                )
            ),

            "last_checked": (
                now_iso()
            ),
        },
    )


def publish_updater_progress(
    host_name,
    running_action=None,
):
    """
    Change only the in_progress field of already-published
    Home Assistant update entities.

    This deliberately avoids Docker, registry and Git scans.
    """

    for entry in list(
        published_update_entities.values()
    ):
        if (
            entry.get("host")
            != host_name
        ):
            continue

        state = dict(
            entry["state"]
        )

        state[
            "in_progress"
        ] = bool(
            running_action
            and
            entry.get("action")
            == running_action
        )

        entry[
            "state"
        ] = state

        mqtt_publish(
            entry[
                "state_topic"
            ],
            state,
        )


# ===========================================================================
# Host configuration
# ===========================================================================

def load_hosts():
    with open(
        HOSTS_FILE,
        "r",
        encoding="utf-8",
    ) as fh:
        data = json.load(
            fh
        )

    return data[
        "hosts"
    ]


# ===========================================================================
# Registry-cache management
# ===========================================================================

def invalidate_image_cache(
    image
):
    image = canonical_image(
        image
    )

    remote_cache.pop(
        image,
        None,
    )

    repo = dockerhub_repository(
        image
    )

    if repo:
        dockerhub_tag_cache.pop(
            repo,
            None,
        )


# ===========================================================================
# Custom base-image support
# ===========================================================================

def handle_base_image_container(
    host_name,
    local,
    labels,
):
    base_image = (
        labels.get(
            "homelab.update.base-image"
        )

        or labels.get(
            "org.opencontainers.image.base.name"
        )
    )

    version_env = (
        labels.get(
            "homelab.update.version-env"
        )
    )

    version_mode = str(
        labels.get(
            "homelab.update.version-mode",
            "",
        )
    ).strip().lower()

    if not base_image:
        print(
            f"[custom] "
            f"{host_name}/"
            f"{local['container']}: "
            f"base-image strategy has "
            f"no base image",
            flush=True,
        )

        return

    base_image = (
        canonical_image(
            base_image
        )
    )

    if (
        base_image
        not in remote_cache
    ):
        try:
            remote_cache[
                base_image
            ] = remote_image_info(
                base_image
            )

        except subprocess.TimeoutExpired:
            print(
                f"[custom] "
                f"{host_name}/"
                f"{local['container']}: "
                f"base-image registry lookup "
                f"timed out after "
                f"{SKOPEO_TIMEOUT}s "
                f"({base_image})",
                flush=True,
            )

            return

        except Exception as exc:
            print(
                f"[custom] "
                f"{host_name}/"
                f"{local['container']}: "
                f"cannot inspect base image "
                f"{base_image}: "
                f"{exc}",
                flush=True,
            )

            return

    remote = dict(
        remote_cache[
            base_image
        ]
    )

    remote[
        "labels"
    ] = dict(
        remote.get(
            "labels"
        )
        or {}
    )

    installed_version = None
    available_version = None

    installed_revision = None
    available_revision = None

    comparison_method = None
    update_available = None

    local_publish = dict(
        local
    )

    local_publish[
        "source_version_raw"
    ] = local.get(
        "version"
    )

    remote[
        "source_version_raw"
    ] = remote.get(
        "version"
    )

    # -----------------------------------------------------------------------
    # Revision mode
    # -----------------------------------------------------------------------

    if (
        version_mode
        == "revision"
    ):
        remote_labels = (
            remote.get(
                "labels"
            )
            or {}
        )

        local_labels = (
            local.get(
                "labels"
            )
            or {}
        )

        available_revision = (
            remote_labels.get(
                "org.opencontainers.image.revision"
            )
        )

        installed_revision = (
            labels.get(
                "homelab.update.base-revision"
            )
        )

        # Safe fallback only if both local and remote provenance
        # point at the same source repository.
        if not installed_revision:
            local_source = (
                local_labels.get(
                    "org.opencontainers.image.source"
                )
            )

            remote_source = (
                remote_labels.get(
                    "org.opencontainers.image.source"
                )
            )

            if same_source(
                local_source,
                remote_source,
            ):
                installed_revision = (
                    local_labels.get(
                        "org.opencontainers.image.revision"
                    )
                )

        if (
            not installed_revision
            or not available_revision
        ):
            print(
                f"[custom] "
                f"{host_name}/"
                f"{local['container']}: "
                f"revision mode cannot determine "
                f"installed/upstream revision",
                flush=True,
            )

            return

        channel = (
            remote.get(
                "version"
            )
        )

        installed_version = (
            revision_display(
                installed_revision,
                channel,
            )
        )

        available_version = (
            revision_display(
                available_revision,
                channel,
            )
        )

        update_available = (
            str(
                installed_revision
            ).strip()
            !=
            str(
                available_revision
            ).strip()
        )

        comparison_method = (
            "source-revision"
        )

    # -----------------------------------------------------------------------
    # Normal / version-env mode
    # -----------------------------------------------------------------------

    else:
        if version_env:
            installed_version = (
                local
                .get("env", {})
                .get(
                    version_env
                )
            )

            available_version = (
                remote
                .get("env", {})
                .get(
                    version_env
                )
            )

        if not installed_version:
            installed_version = (
                resolve_pretty_version(
                    local
                )
            )

        if not available_version:
            available_version = (
                resolve_pretty_version(
                    remote
                )
            )

        built_from_digest = (
            labels.get(
                "org.opencontainers.image.base.digest"
            )

            or labels.get(
                "homelab.update.base-digest"
            )
        )

        latest_base_digest = (
            remote.get(
                "digest"
            )
        )

        if (
            built_from_digest
            and latest_base_digest
        ):
            update_available = (
                str(
                    built_from_digest
                ).strip()
                !=
                str(
                    latest_base_digest
                ).strip()
            )

            comparison_method = (
                "base-digest"
            )

        elif (
            installed_version
            and available_version
        ):
            comparison = (
                version_update_available(
                    installed_version,
                    available_version,
                )
            )

            if (
                comparison
                is not None
            ):
                update_available = (
                    comparison
                )

                comparison_method = (
                    "version-aware"
                )

            else:
                update_available = (
                    str(
                        installed_version
                    )
                    !=
                    str(
                        available_version
                    )
                )

                comparison_method = (
                    "version-string"
                )

        else:
            print(
                f"[custom] "
                f"{host_name}/"
                f"{local['container']}: "
                f"cannot determine installed/"
                f"available base version",
                flush=True,
            )

            return

    built_from_digest = (
        labels.get(
            "org.opencontainers.image.base.digest"
        )

        or labels.get(
            "homelab.update.base-digest"
        )
    )

    local_publish[
        "custom_image"
    ] = True

    local_publish[
        "custom_update_available"
    ] = bool(
        update_available
    )

    local_publish[
        "update_strategy"
    ] = "base-image"

    local_publish[
        "base_image"
    ] = base_image

    local_publish[
        "base_digest"
    ] = built_from_digest

    local_publish[
        "comparison_method"
    ] = comparison_method

    local_publish[
        "version_env"
    ] = version_env

    local_publish[
        "version_mode"
    ] = (
        version_mode
        or None
    )

    local_publish[
        "upstream_version"
    ] = available_version

    local_publish[
        "installed_base_revision"
    ] = installed_revision

    local_publish[
        "available_base_revision"
    ] = available_revision

    if installed_version:
        local_publish[
            "version"
        ] = installed_version

    if available_version:
        remote[
            "version"
        ] = available_version

    print(
        f"[custom] "
        f"{host_name}/"
        f"{local['container']}: "
        f"{installed_version or '?'} "
        f"-> "
        f"{available_version or '?'} "
        f"({comparison_method})"
        f"{' UPDATE' if update_available else ''}",
        flush=True,
    )

    publish_entity(
        host_name,
        local_publish,
        remote,
    )


# ===========================================================================
# Git-revision support
# ===========================================================================

def handle_git_revision_container(
    host_name,
    local,
    labels,
):
    repository = (
        labels.get(
            "homelab.update.git-repo"
        )
    )

    branch = (
        labels.get(
            "homelab.update.git-branch"
        )
        or "main"
    )

    installed_revision = (
        labels.get(
            "homelab.update.source-revision"
        )
    )

    if not repository:
        print(
            f"[git] "
            f"{host_name}/"
            f"{local['container']}: "
            f"missing homelab.update.git-repo",
            flush=True,
        )

        return

    if not installed_revision:
        print(
            f"[git] "
            f"{host_name}/"
            f"{local['container']}: "
            f"missing homelab.update.source-revision "
            f"on built image",
            flush=True,
        )

        return

    installed_revision = str(
        installed_revision
    ).strip()

    try:
        available_revision = (
            github_branch_revision(
                repository,
                branch,
            )
        )

    except Exception as exc:
        print(
            f"[git] "
            f"{host_name}/"
            f"{local['container']}: "
            f"cannot resolve "
            f"{repository}/{branch}: "
            f"{exc}",
            flush=True,
        )

        return

    update_available = (
        installed_revision
        != available_revision
    )

    installed_version = (
        revision_display(
            installed_revision,
            branch,
        )
    )

    available_version = (
        revision_display(
            available_revision,
            branch,
        )
    )

    local_publish = dict(
        local
    )

    local_publish[
        "custom_image"
    ] = True

    local_publish[
        "custom_update_available"
    ] = update_available

    local_publish[
        "update_strategy"
    ] = "git-revision"

    local_publish[
        "comparison_method"
    ] = "git-revision"

    local_publish[
        "version"
    ] = installed_version

    local_publish[
        "source_version_raw"
    ] = installed_revision

    local_publish[
        "upstream_version"
    ] = available_version

    local_publish[
        "git_repository"
    ] = repository

    local_publish[
        "git_branch"
    ] = branch

    local_publish[
        "installed_source_revision"
    ] = installed_revision

    local_publish[
        "available_source_revision"
    ] = available_revision

    # Pseudo-remote metadata so the normal HA publishing path can be reused.
    remote = {
        "image": (
            f"github:{repository}:{branch}"
        ),

        "digest": None,

        "labels": {
            "org.opencontainers.image.title": (
                "Obico Server"
                if repository.lower()
                == "thespaghettidetective/obico-server"
                else repository.split("/")[-1]
            ),

            "org.opencontainers.image.source": (
                f"https://github.com/"
                f"{repository}"
            ),

            "org.opencontainers.image.url": (
                f"https://github.com/"
                f"{repository}/commits/"
                f"{quote(branch, safe='')}"
            ),

            "org.opencontainers.image.version": (
                branch
            ),

            "org.opencontainers.image.revision": (
                available_revision
            ),
        },

        "env": {},

        "version": (
            available_version
        ),

        "source_version_raw": (
            available_revision
        ),

        "created": None,

        "architecture": None,

        "os": None,
    }

    print(
        f"[git] "
        f"{host_name}/"
        f"{local['container']}: "
        f"{installed_version} "
        f"-> "
        f"{available_version} "
        f"(git-revision)"
        f"{' UPDATE' if update_available else ''}",
        flush=True,
    )

    publish_entity(
        host_name,
        local_publish,
        remote,
    )


# ===========================================================================
# Host scanning
# ===========================================================================

def scan_host(
    host,
    refresh_remote=False,
    only_image=None,
):
    host_name = (
        host["name"]
    )

    endpoint = (
        host["endpoint"]
    )

    print(
        f"[scan] "
        f"{host_name}",
        flush=True,
    )

    containers = docker_get(
        endpoint,
        "/containers/json?all=1",
    )

    for container in containers:
        try:
            # ---------------------------------------------------------------
            # EARLY skip.
            #
            # /containers/json already contains Compose/container labels.
            # Do this before /images/<sha>/json so completely excluded local
            # images such as mqtt-publisher never need image inspection.
            # ---------------------------------------------------------------

            summary_labels = (
                container.get(
                    "Labels"
                )
                or {}
            )

            early_strategy = str(
                summary_labels.get(
                    "homelab.update.strategy",
                    "",
                )
            ).strip().lower()

            early_disabled = (
                str(
                    summary_labels.get(
                        "diun.enable",
                        "",
                    )
                ).strip().lower()
                == "false"
            )

            if (
                early_disabled
                and early_strategy
                not in CUSTOM_STRATEGIES
            ):
                print(
                    f"[skip] "
                    f"{host_name}/"
                    f"{container_display_name(container)}: "
                    f"diun.enable=false",
                    flush=True,
                )

                continue

            # ---------------------------------------------------------------
            # Full container/image information
            # ---------------------------------------------------------------

            local = (
                local_image_info(
                    host,
                    container,
                )
            )

            labels = (
                local.get(
                    "labels"
                )
                or {}
            )

            strategy = str(
                labels.get(
                    "homelab.update.strategy",
                    "",
                )
            ).strip().lower()

            # ---------------------------------------------------------------
            # Custom strategies MUST be handled before diun.enable=false.
            # ---------------------------------------------------------------

            if (
                strategy
                == "base-image"
            ):
                handle_base_image_container(
                    host_name,
                    local,
                    labels,
                )

                continue

            if (
                strategy
                == "git-revision"
            ):
                handle_git_revision_container(
                    host_name,
                    local,
                    labels,
                )

                continue

            # ---------------------------------------------------------------
            # Explicit Diun exclusion
            # ---------------------------------------------------------------

            if (
                str(
                    labels.get(
                        "diun.enable",
                        "",
                    )
                ).lower()
                == "false"
            ):
                print(
                    f"[skip] "
                    f"{host_name}/"
                    f"{local['container']}: "
                    f"diun.enable=false",
                    flush=True,
                )

                continue

            # ---------------------------------------------------------------
            # Local image without tracking strategy
            # ---------------------------------------------------------------

            if not local.get(
                "digest"
            ):
                print(
                    f"[skip] "
                    f"{host_name}/"
                    f"{local['container']}: "
                    f"local image has no "
                    f"registry RepoDigest "
                    f"({local['image']})",
                    flush=True,
                )

                continue

            image = (
                canonical_image(
                    local["image"]
                )
            )

            if (
                only_image
                and image
                != canonical_image(
                    only_image
                )
            ):
                continue

            cache_key = (
                image
            )

            if (
                refresh_remote
                or cache_key
                not in remote_cache
            ):
                try:
                    remote_cache[
                        cache_key
                    ] = remote_image_info(
                        image
                    )

                except subprocess.TimeoutExpired:
                    print(
                        f"[registry] "
                        f"{image}: "
                        f"skopeo timed out after "
                        f"{SKOPEO_TIMEOUT}s",
                        flush=True,
                    )

                    if (
                        cache_key
                        not in remote_cache
                    ):
                        continue

                except Exception as exc:
                    print(
                        f"[registry] "
                        f"{image}: "
                        f"{exc}",
                        flush=True,
                    )

                    if (
                        cache_key
                        not in remote_cache
                    ):
                        continue

            remote = (
                remote_cache[
                    cache_key
                ]
            )

            publish_entity(
                host_name,
                local,
                remote,
            )

        except Exception as exc:
            print(
                f"[container] "
                f"{host_name}: "
                f"{container.get('Names')} "
                f"-> {exc}",
                flush=True,
            )

    publish_summary()


def full_scan(
    hosts,
    refresh_remote=False,
):
    if refresh_remote:
        remote_cache.clear()
        dockerhub_tag_cache.clear()
        git_revision_cache.clear()

    for host in hosts:
        try:
            scan_host(
                host,
                refresh_remote=False,
            )

        except Exception as exc:
            print(
                f"[host] "
                f"{host['name']}: "
                f"{exc}",
                flush=True,
            )


# ===========================================================================
# MQTT callbacks
# ===========================================================================

def on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties,
):
    print(
        f"[mqtt] connected: "
        f"{reason_code}",
        flush=True,
    )

    client.subscribe(
        DIUN_EVENT_TOPIC,
        qos=1,
    )

    client.subscribe(
        (
            f"{UPDATER_TOPIC_PREFIX}/"
            f"+/availability"
        ),
        qos=1,
    )

    client.subscribe(
        (
            f"{UPDATER_TOPIC_PREFIX}/"
            f"+/capabilities"
        ),
        qos=1,
    )

    client.subscribe(
        (
            f"{UPDATER_TOPIC_PREFIX}/"
            f"+/status"
        ),
        qos=1,
    )

    mqtt_publish(
        f"{TOPIC_PREFIX}/"
        f"availability",
        "online",
    )


def on_message(
    client,
    userdata,
    msg,
):
    # -----------------------------------------------------------------------
    # Diun events
    # -----------------------------------------------------------------------

    if (
        msg.topic
        == DIUN_EVENT_TOPIC
    ):
        try:
            payload = json.loads(
                msg.payload.decode(
                    "utf-8"
                )
            )

            event_queue.put(
                payload
            )

        except Exception as exc:
            print(
                f"[mqtt] bad Diun event: "
                f"{exc}",
                flush=True,
            )

        return

    # -----------------------------------------------------------------------
    # Homelab updater events
    # -----------------------------------------------------------------------

    prefix = (
        f"{UPDATER_TOPIC_PREFIX}/"
    )

    if not msg.topic.startswith(
        prefix
    ):
        return

    remainder = msg.topic[
        len(prefix):
    ]

    parts = remainder.split(
        "/"
    )

    if len(parts) != 2:
        return

    host_name, event_type = (
        parts
    )

    if event_type not in {
        "availability",
        "capabilities",
        "status",
    }:
        return

    updater_event_queue.put(
        {
            "host": host_name,

            "type": event_type,

            "payload": (
                msg.payload.decode(
                    "utf-8"
                )
            ),
        }
    )


# ===========================================================================
# Diun event worker
# ===========================================================================

def event_worker(
    hosts
):
    host_map = {
        host["name"]: host
        for host in hosts
    }

    while True:
        event = (
            event_queue.get()
        )

        try:
            hostname = (
                event.get(
                    "hostname"
                )
            )

            image = (
                event.get(
                    "image"
                )
            )

            print(
                f"[diun] event "
                f"host={hostname} "
                f"image={image}",
                flush=True,
            )

            host = (
                host_map.get(
                    hostname
                )
            )

            if (
                not host
                or not image
            ):
                print(
                    "[diun] event does not "
                    "match configured host",
                    flush=True,
                )

                continue

            invalidate_image_cache(
                image
            )

            scan_host(
                host,
                refresh_remote=False,
                only_image=image,
            )

        except Exception as exc:
            print(
                f"[diun] event error: "
                f"{exc}",
                flush=True,
            )

        finally:
            event_queue.task_done()


def updater_event_worker(
    hosts
):
    host_map = {
        host["name"]: host
        for host in hosts
    }

    while True:
        event = (
            updater_event_queue.get()
        )

        try:
            host_name = (
                event["host"]
            )

            event_type = (
                event["type"]
            )

            raw = (
                event["payload"]
            )

            host = (
                host_map.get(
                    host_name
                )
            )

            if not host:
                print(
                    f"[updater] ignoring "
                    f"unknown host "
                    f"{host_name}",
                    flush=True,
                )

                continue

            # ---------------------------------------------------------------
            # Agent availability
            # ---------------------------------------------------------------

            if (
                event_type
                == "availability"
            ):
                online = (
                    raw.strip().lower()
                    == "online"
                )

                previous = (
                    updater_online.get(
                        host_name
                    )
                )

                updater_online[
                    host_name
                ] = online

                print(
                    f"[updater] "
                    f"{host_name}: "
                    f"{'online' if online else 'offline'}",
                    flush=True,
                )

                # Installability may have changed.
                #
                # Re-publish discovery/config so command_topic appears
                # or disappears as appropriate.
                if (
                    previous
                    != online
                ):
                    scan_host(
                        host,
                        refresh_remote=False,
                    )

            # ---------------------------------------------------------------
            # Agent capabilities
            # ---------------------------------------------------------------

            elif (
                event_type
                == "capabilities"
            ):
                payload = json.loads(
                    raw
                )

                actions = (
                    payload.get(
                        "actions"
                    )
                    or {}
                )

                if not isinstance(
                    actions,
                    dict,
                ):
                    actions = {}

                previous = (
                    updater_capabilities.get(
                        host_name
                    )
                )

                updater_capabilities[
                    host_name
                ] = actions

                print(
                    f"[updater] "
                    f"{host_name}: "
                    f"actions="
                    f"{','.join(actions.keys())}",
                    flush=True,
                )

                # Only rescan if capabilities actually changed.
                if (
                    previous
                    != actions
                ):
                    scan_host(
                        host,
                        refresh_remote=False,
                    )

            # ---------------------------------------------------------------
            # Agent state
            # ---------------------------------------------------------------

            elif (
                event_type
                == "status"
            ):
                payload = json.loads(
                    raw
                )

                if not isinstance(
                    payload,
                    dict,
                ):
                    return

                updater_status[
                    host_name
                ] = payload

                state = (
                    payload.get(
                        "state"
                    )
                )

                action = (
                    payload.get(
                        "action"
                    )
                )

                print(
                    f"[updater] "
                    f"{host_name}: "
                    f"{state} "
                    f"{action or ''}",
                    flush=True,
                )

                # Fast UI-only progress update.
                #
                # Do not perform Docker or registry scans just to update
                # the Home Assistant spinner.
                if (
                    state
                    == "running"
                ):
                    publish_updater_progress(
                        host_name,
                        action,
                    )

                else:
                    publish_updater_progress(
                        host_name,
                        None,
                    )

                # A successful updater run is the signal to verify the
                # actual installed state immediately.
                #
                # The detector remains authoritative: do NOT blindly mark
                # the entity current simply because the script returned 0.
                if (
                    state
                    == "success"
                ):
                    scan_host(
                        host,
                        refresh_remote=False,
                    )

        except Exception as exc:
            print(
                f"[updater] event error: "
                f"{exc}",
                flush=True,
            )

        finally:
            updater_event_queue.task_done()


# ===========================================================================
# Startup
# ===========================================================================

hosts = load_hosts()


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id=(
        "diun-ha-bridge"
    ),
)


if MQTT_USERNAME:
    client.username_pw_set(
        MQTT_USERNAME,
        MQTT_PASSWORD,
    )


client.will_set(
    f"{TOPIC_PREFIX}/"
    f"availability",
    "offline",
    qos=1,
    retain=True,
)


client.on_connect = (
    on_connect
)

client.on_message = (
    on_message
)


client.connect(
    MQTT_HOST,
    MQTT_PORT,
    keepalive=60,
)


client.loop_start()


threading.Thread(
    target=event_worker,
    args=(hosts,),
    daemon=True,
).start()


threading.Thread(
    target=updater_event_worker,
    args=(hosts,),
    daemon=True,
).start()


print(
    "[startup] initial registry "
    "+ Docker + Git scan",
    flush=True,
)


full_scan(
    hosts,
    refresh_remote=True,
)


last_remote_scan = (
    time.monotonic()
)


# ===========================================================================
# Main loop
# ===========================================================================

while True:
    time.sleep(
        LOCAL_SCAN_INTERVAL
    )

    remote_due = (
        time.monotonic()
        - last_remote_scan
        >= REMOTE_SCAN_INTERVAL
    )

    full_scan(
        hosts,
        refresh_remote=remote_due,
    )

    if remote_due:
        last_remote_scan = (
            time.monotonic()
        )
