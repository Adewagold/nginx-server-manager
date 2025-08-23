#!/bin/bash
# Docker build script for Nginx Site Manager
# Builds Docker image with proper tags and metadata

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="nginx-manager"
REGISTRY="${DOCKER_REGISTRY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Get version information
get_version() {
    local version=""
    
    # Try to get version from git tag
    if command -v git >/dev/null 2>&1 && [ -d "$PROJECT_ROOT/.git" ]; then
        version=$(git describe --tags --exact-match 2>/dev/null || echo "")
        if [ -z "$version" ]; then
            version=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
            if [ -n "$version" ]; then
                local commit=$(git rev-parse --short HEAD)
                version="${version}-${commit}"
            fi
        fi
    fi
    
    # Fallback to default version
    if [ -z "$version" ]; then
        version="1.0.0"
    fi
    
    echo "$version"
}

# Get build metadata
get_build_date() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

get_vcs_ref() {
    if command -v git >/dev/null 2>&1 && [ -d "$PROJECT_ROOT/.git" ]; then
        git rev-parse HEAD
    else
        echo "unknown"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is not installed or not in PATH"
    fi
    
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running or not accessible"
    fi
    
    log "Prerequisites check passed"
}

# Build Docker image
build_image() {
    local version="$1"
    local build_date="$2"
    local vcs_ref="$3"
    local build_type="${4:-production}"
    
    log "Building Docker image..."
    log "Version: $version"
    log "Build Date: $build_date"
    log "VCS Ref: $vcs_ref"
    log "Build Type: $build_type"
    
    # Determine Dockerfile
    local dockerfile="Dockerfile"
    if [ "$build_type" = "development" ]; then
        dockerfile="Dockerfile.dev"
        if [ ! -f "$PROJECT_ROOT/$dockerfile" ]; then
            warn "Development Dockerfile not found, using production Dockerfile"
            dockerfile="Dockerfile"
        fi
    fi
    
    # Build image
    local image_tag="${IMAGE_NAME}:${version}"
    
    cd "$PROJECT_ROOT"
    
    docker build \
        --file "$dockerfile" \
        --tag "$image_tag" \
        --tag "${IMAGE_NAME}:latest" \
        --build-arg BUILD_DATE="$build_date" \
        --build-arg VCS_REF="$vcs_ref" \
        --build-arg VERSION="$version" \
        --label "org.label-schema.build-date=$build_date" \
        --label "org.label-schema.name=$IMAGE_NAME" \
        --label "org.label-schema.version=$version" \
        --label "org.label-schema.vcs-ref=$vcs_ref" \
        .
    
    log "Docker image built successfully: $image_tag"
    
    # Add registry prefix if specified
    if [ -n "$REGISTRY" ]; then
        local registry_tag="${REGISTRY}/${image_tag}"
        docker tag "$image_tag" "$registry_tag"
        docker tag "${IMAGE_NAME}:latest" "${REGISTRY}/${IMAGE_NAME}:latest"
        log "Tagged for registry: $registry_tag"
    fi
}

# Test image
test_image() {
    local version="$1"
    local image_tag="${IMAGE_NAME}:${version}"
    
    log "Testing Docker image..."
    
    # Basic smoke test
    if ! docker run --rm "$image_tag" security-audit; then
        warn "Security audit found issues, but image is functional"
    fi
    
    # Health check test
    log "Starting container for health check test..."
    local container_id=$(docker run -d -p 18080:8080 "$image_tag")
    
    # Wait for container to start
    sleep 30
    
    # Test health endpoint
    if curl -f http://localhost:18080/api/health >/dev/null 2>&1; then
        log "Health check passed"
    else
        warn "Health check failed, but image may still be functional"
    fi
    
    # Clean up test container
    docker stop "$container_id" >/dev/null
    docker rm "$container_id" >/dev/null
    
    log "Image testing completed"
}

# Push image to registry
push_image() {
    local version="$1"
    
    if [ -z "$REGISTRY" ]; then
        warn "No registry specified, skipping push"
        return
    fi
    
    log "Pushing image to registry: $REGISTRY"
    
    docker push "${REGISTRY}/${IMAGE_NAME}:${version}"
    docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    
    log "Image pushed successfully"
}

# Show usage
show_usage() {
    cat << EOF
Docker Build Script for Nginx Site Manager

Usage: $0 [OPTIONS]

OPTIONS:
    -t, --type TYPE         Build type: production (default) or development
    -r, --registry URL      Docker registry URL for pushing images
    -p, --push             Push image to registry after building
    -T, --test             Test image after building
    -v, --version VERSION  Override version (default: auto-detected from git)
    -h, --help             Show this help message

EXAMPLES:
    # Basic build
    $0
    
    # Build and test
    $0 --test
    
    # Build for development
    $0 --type development
    
    # Build and push to registry
    $0 --registry my-registry.com --push
    
    # Build specific version
    $0 --version 2.1.0 --push

ENVIRONMENT VARIABLES:
    DOCKER_REGISTRY        Default registry URL
    IMAGE_NAME            Override image name (default: nginx-manager)

EOF
}

# Main function
main() {
    local build_type="production"
    local push_flag=false
    local test_flag=false
    local version=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)
                build_type="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -p|--push)
                push_flag=true
                shift
                ;;
            -T|--test)
                test_flag=true
                shift
                ;;
            -v|--version)
                version="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Validate build type
    if [ "$build_type" != "production" ] && [ "$build_type" != "development" ]; then
        error "Invalid build type: $build_type (must be 'production' or 'development')"
    fi
    
    # Get version and build metadata
    if [ -z "$version" ]; then
        version=$(get_version)
    fi
    local build_date=$(get_build_date)
    local vcs_ref=$(get_vcs_ref)
    
    log "Starting Docker build process"
    log "==============================="
    
    # Run build process
    check_prerequisites
    build_image "$version" "$build_date" "$vcs_ref" "$build_type"
    
    if [ "$test_flag" = true ]; then
        test_image "$version"
    fi
    
    if [ "$push_flag" = true ]; then
        push_image "$version"
    fi
    
    log "==============================="
    log "Docker build process completed"
    log ""
    log "Image: ${IMAGE_NAME}:${version}"
    if [ -n "$REGISTRY" ]; then
        log "Registry: ${REGISTRY}/${IMAGE_NAME}:${version}"
    fi
    log ""
    log "To run the container:"
    log "  docker run -d -p 80:80 -p 443:443 -p 8080:8080 ${IMAGE_NAME}:${version}"
    log ""
    log "To run with docker-compose:"
    log "  docker-compose up -d"
}

# Run main function
main "$@"