FROM python:3.12-slim-trixie@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ARG CONTROLLER_UID=1000
ARG CONTROLLER_GID=1000
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssh-client openssl curl git unzip util-linux rsync jq \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt collections.yml tools.lock.json install-tools.py /bootstrap/
RUN pip install --no-cache-dir -r /bootstrap/requirements.txt \
    && python /bootstrap/install-tools.py \
    && ansible-galaxy collection install -r /bootstrap/collections.yml -p /opt/ansible/collections \
    && groupadd -o -g ${CONTROLLER_GID} controller \
    && useradd -o -m -u ${CONTROLLER_UID} -g ${CONTROLLER_GID} -s /bin/bash controller \
    && chmod -R a+rX /opt/ansible
ENV ANSIBLE_COLLECTIONS_PATH=/opt/ansible/collections:/workspace/collections
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER controller
WORKDIR /workspace
ENTRYPOINT ["python3"]
