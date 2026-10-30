"""Create or update the containerizer comment on an Azure Repos pull request.

Uses the pipeline's System.AccessToken (passed as SYSTEM_ACCESSTOKEN) and the predefined variables of a
PR build. Exits 0 with a warning when the comment cannot be posted, so the gate result decides the build."""
import json
import os
import sys
import urllib.error
import urllib.request

MARKER = "<!-- containerizer-check -->"


def call(method: str, url: str, token: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def main(md_file: str) -> int:
    env = os.environ
    token = env.get("SYSTEM_ACCESSTOKEN")
    pr = env.get("SYSTEM_PULLREQUEST_PULLREQUESTID")
    if not token or not pr:
        print("##vso[task.logissue type=warning]no pull request or access token; skipping the PR comment")
        return 0
    if env.get("BUILD_REPOSITORY_PROVIDER", "TfsGit") != "TfsGit":
        print("##vso[task.logissue type=warning]PR comments are only supported for Azure Repos; see the build summary")
        return 0
    body = open(md_file, encoding="utf-8").read()
    base = (f"{env['SYSTEM_COLLECTIONURI'].rstrip('/')}/{env['SYSTEM_TEAMPROJECTID']}/_apis/git/repositories/"
            f"{env['BUILD_REPOSITORY_ID']}/pullRequests/{pr}/threads")
    v = "api-version=7.1"
    try:
        for t in call("GET", f"{base}?{v}", token).get("value", []):
            first = (t.get("comments") or [{}])[0]
            if (first.get("content") or "").startswith(MARKER):
                call("PATCH", f"{base}/{t['id']}/comments/{first['id']}?{v}", token, {"content": body})
                print(f"updated PR comment in thread {t['id']}")
                return 0
        t = call("POST", f"{base}?{v}", token,
                 {"comments": [{"parentCommentId": 0, "content": body, "commentType": 1}], "status": 1})
        print(f"created PR comment thread {t.get('id')}")
    except (urllib.error.URLError, KeyError) as e:
        print(f"##vso[task.logissue type=warning]could not comment on the pull request: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
