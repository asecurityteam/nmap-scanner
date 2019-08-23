FROM asecurityteam/serverfull-gateway
COPY api.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="api.yaml"
