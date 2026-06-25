image := "openhost-vaultwarden"
data  := justfile_directory() / ".local-data"

# Build the Docker image
build:
    podman build -t {{image}} .

# Build and run locally on http://localhost:8080
serve: build
    @mkdir -p {{data}}
    podman run --rm -it \
        -p 8080:8080 \
        -e PUBLIC_HOSTNAME=localhost:8080 \
        -e DOMAIN=http://localhost:8080 \
        -e OPENHOST_APP_DATA_DIR=/data/app_data/vaultwarden \
        -v "{{data}}:/data/app_data/vaultwarden" \
        {{image}}
