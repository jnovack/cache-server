# cache-server

## Docker

### Persistent Cache Directory

This container uses `/cache` to store persistent data. To retain cache across restarts, mount a local directory:

```bash
docker run -p 8080:8080 \
  -e DOMAIN=contoso.local \
  -v $(pwd)/cache:/cache \
  cache-server
```
