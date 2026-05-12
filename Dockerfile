# Dockerfile — self-hosted Skill Scanner deployment
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Skill Scanner"
LABEL org.opencontainers.image.description="Agent Skill Surface Diff — scan Agent Skills for security risks"
LABEL org.opencontainers.image.source="https://github.com/jasoneip01-pixel/skill-scanner"
LABEL org.opencontainers.image.version="0.3.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install OPA for Rego policy engine
RUN curl -sSL -o /usr/local/bin/opa \
    https://openpolicyagent.org/downloads/latest/opa_linux_amd64 \
    && chmod +x /usr/local/bin/opa

WORKDIR /app

COPY pyproject.toml README.md ./
COPY skill_scanner/ ./skill_scanner/

RUN pip install --no-cache-dir -e .

# Non-root user
RUN useradd -m -s /bin/bash scanner
USER scanner

VOLUME ["/skills", "/policies", "/reports"]

ENTRYPOINT ["agent-skills"]
CMD ["scan", "/skills"]
