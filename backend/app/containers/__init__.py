"""Container security: Dockerfile / Compose linting and offline image analysis.

* :mod:`app.containers.dockerfile` - static checks of Dockerfiles and Compose files (text only)
* :mod:`app.containers.image` - analysis of a ``docker save`` / OCI image archive held in memory
* :mod:`app.containers.trivy` - optional vulnerability scan through an installed Trivy binary

Nothing here runs a container, pulls an image or executes image content.
"""
