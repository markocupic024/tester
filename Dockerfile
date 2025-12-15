FROM mambaorg/micromamba:1.5.8

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    build-essential \
    chromium \
    chromium-driver \
    nodejs \
    npm \
    default-jre \
    unzip \
    dnsutils \
    openssl \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js tools
RUN npm install -g \
    lighthouse \
    pa11y \
    npm-check-updates

# Create app directory
WORKDIR /app

# Copy conda environment file
COPY environment.yml .

# Create conda environment with Python packages
RUN micromamba install -y -n base -f environment.yml && \
    micromamba clean --all --yes

# Activate conda environment
ARG MAMBA_DOCKERFILE_ACTIVATE=1

# Install additional Python packages
RUN micromamba run -n base pip install --no-cache-dir \
    reportlab \
    beautifulsoup4 \
    requests \
    validators \
    dnspython \
    lxml

# Install sslyze
RUN micromamba run -n base pip install --no-cache-dir sslyze

# Install Nuclei (optional - uncomment if needed)
# RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.6.0/nuclei_3.6.0_linux_arm.zip && \
#    unzip nuclei_3.6.0_linux_arm.zip && \
#    mv nuclei /usr/local/bin/ && \
#    rm nuclei_3.6.0_linux_arm.zip && \
#    nuclei -update-templates

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# Copy application
COPY tester.py .

# Make script executable
RUN chmod +x tester.py

# Set environment variables for Chromium/Puppeteer
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROME_PATH=/usr/bin/chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Create output directory
RUN mkdir -p /output

# Set working directory for outputs
VOLUME /output

# Entry point
ENTRYPOINT ["micromamba", "run", "-n", "base", "python", "tester.py"]
CMD ["--help"]
