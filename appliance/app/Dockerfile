# syntax=docker/dockerfile:1.7
# The app update of a release (containerizer/apppatch.py): only the application, for appliances that run an
# earlier release of the same series (vX.Y). A patch release does not change the OS, so they install this small
# image instead of the whole OS image, and only their containerizer services restart.
# The release workflow assembles the build context (build/app):
#   app/manifest.json     {"version": "vX.Y.Z", "series": "X.Y", "requirements_sha256": "<appliance/requirements.lock>"}
#   app/containerizer/    the package
#   app/rules/            the rules, without learned/ (the appliance keeps those on its persistent partition)
FROM scratch
COPY app/ /app/
LABEL org.opencontainers.image.title="containerizer app update" \
      org.opencontainers.image.description="The containerizer application of a release, installed on appliances of the same release series without an OS upgrade" \
      org.opencontainers.image.source="https://github.com/olljanat-ai/containerizer"
