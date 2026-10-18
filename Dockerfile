FROM python:3.12-slim

# Utilisateur non privilegie ; /data est le volume des donnees (etat, jeton, outbox)
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin wifiguard \
 && mkdir -p /app /data && chown 1000:1000 /data && chmod 750 /data

COPY wifi_guard.py /app/wifi_guard.py

ENV WG_DATA=/data PYTHONUNBUFFERED=1
USER 1000:1000
VOLUME ["/data"]
CMD ["python", "-u", "/app/wifi_guard.py", "run"]
