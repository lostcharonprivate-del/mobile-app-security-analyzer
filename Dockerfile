# Reproducible analysis environment.
#
# The analyzer works with no external tooling at all — the DEX, AXML, ARSC and
# Mach-O readers are pure Python. This image exists so that apktool and jadx are
# available too, without asking anyone to hand-install reverse-engineering tools.
FROM python:3.14-slim-bookworm

ARG APKTOOL_VERSION=2.9.3
ARG JADX_VERSION=1.5.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MASA_IN_CONTAINER=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jre-headless \
        unzip \
        curl \
        ca-certificates \
        binutils \
    && rm -rf /var/lib/apt/lists/*

# apktool: resource and manifest decoding.
RUN curl -fsSL -o /usr/local/bin/apktool \
      "https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool" \
 && curl -fsSL -o /usr/local/bin/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
 && chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# jadx: DEX to Java source.
RUN curl -fsSL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
 && unzip -q /tmp/jadx.zip -d /opt/jadx \
 && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && rm /tmp/jadx.zip

WORKDIR /app
COPY pyproject.toml README.md ./
COPY masa ./masa
RUN pip install --no-cache-dir .

# Analysis runs as an unprivileged user: this process opens untrusted archives
# and hands them to third-party decompilers, so it should own as little as possible.
RUN useradd --create-home --shell /usr/sbin/nologin analyst \
 && mkdir -p /work /scratch \
 && chown analyst:analyst /work /scratch
USER analyst
ENV TMPDIR=/scratch

WORKDIR /work
ENTRYPOINT ["masa"]
CMD ["--help"]
