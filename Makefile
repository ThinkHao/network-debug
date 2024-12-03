VERSION := 1.0.0
TARGET := net-tracer
BUILD_DIR := build

# Docker parameters
DOCKER_IMAGE := golang:1.22-bullseye
DOCKER_BUILD_IMAGE := net-tracer-builder
DOCKER_WORKDIR := /workspace

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOGET := $(GOCMD) get

# BPF parameters
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
ARCH := x86_64
CENTOS_TARGET := linux/amd64

# 确保使用静态链接和较老的 GLIBC 特性级别
LDFLAGS := -ldflags="-s -w -extldflags '-static'"
GOFLAGS := CGO_ENABLED=1 GOOS=linux GOARCH=amd64 GOAMD64=v1

.PHONY: all
all: docker-build

# 创建 Docker 构建镜像
.PHONY: docker-image
docker-image:
	docker build -t $(DOCKER_BUILD_IMAGE) -f docker/Dockerfile.build .

# 在 Docker 中构建
.PHONY: docker-build
docker-build: docker-image
	docker run --rm -v $(PWD):$(DOCKER_WORKDIR) \
		$(DOCKER_BUILD_IMAGE) \
		make build-in-docker

# Docker 内部构建命令
.PHONY: build-in-docker
build-in-docker: generate
	mkdir -p $(BUILD_DIR)
	$(GOFLAGS) $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(TARGET)

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -I/usr/include -I/usr/include/asm -I/usr/include/clang-include
generate:
	$(GOCMD) generate ./...

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f bpf_bpfel.go bpf_bpfel.o

.PHONY: deps
deps:
	$(GOGET) -u github.com/cilium/ebpf
	$(GOGET) -u github.com/aquasecurity/libbpfgo

# 创建发布包
.PHONY: release
release: docker-build
	mkdir -p $(BUILD_DIR)/$(TARGET)-$(VERSION)
	cp $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/$(TARGET)-$(VERSION)/
	cp README.md $(BUILD_DIR)/$(TARGET)-$(VERSION)/
	cd $(BUILD_DIR) && tar czf $(TARGET)-$(VERSION)-$(ARCH).tar.gz $(TARGET)-$(VERSION)

# 打印版本信息
.PHONY: version
version:
	@echo $(VERSION)

# 帮助信息
.PHONY: help
help:
	@echo "Management commands for net-tracer:"
	@echo
	@echo "Usage:"
	@echo "    make docker-build    Build the binary for CentOS 7.9 using Docker"
	@echo "    make clean           Clean build directory"
	@echo "    make deps            Install dependencies"
	@echo "    make release         Create release package"
	@echo "    make version         Show version information"
	@echo
	@echo "Version: $(VERSION)"
