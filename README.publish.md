```
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/archery-club/supabase-auth:latest .
docker push ghcr.io/archery-club/supabase-auth:latest
```