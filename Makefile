# Persona 数字身份管理系统 Makefile

.PHONY: help build test clean docs docs-serve docs-build docs-deploy install dev setup js-install extension-build web-dev web-build

# 默认目标
help: ## 显示帮助信息
	@echo "Persona 数字身份管理系统"
	@echo ""
	@echo "可用命令:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# 安装依赖
install: ## 安装所有依赖
	@echo "安装 Rust 依赖..."
	cargo fetch
	@echo "安装桌面应用依赖..."
	cd desktop && npm install
	@echo "安装移动应用依赖..."
	cd mobile && flutter pub get
	@echo "依赖安装完成!"

js-install: ## 安装 JS 依赖（pnpm workspace）
	pnpm install

extension-build: ## 构建 Chromium 浏览器扩展
	pnpm --filter persona-chromium-extension run build

web-dev: ## 启动网站开发服务器
	pnpm --filter persona-website run dev

web-build: ## 构建网站
	pnpm --filter persona-website run build

# 开发环境设置
setup: install ## 设置开发环境
	@echo "检查开发环境..."
	@command -v cargo >/dev/null 2>&1 || { echo "请先安装 Rust"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "请先安装 Node.js"; exit 1; }
	@command -v flutter >/dev/null 2>&1 || { echo "请先安装 Flutter"; exit 1; }
	@command -v mdbook >/dev/null 2>&1 || { echo "安装 mdbook..."; cargo install mdbook; }
	@echo "开发环境设置完成!"

# 构建项目
build: ## 构建所有组件
	@echo "构建核心库 (workspace)..."
	cargo build --workspace --release
	@echo "构建桌面应用..."
	cd desktop && npm run tauri build
	@echo "构建移动应用..."
	cd mobile && flutter build apk
	@echo "构建完成!"

build-all: build ## 构建所有组件（别名）

# 开发模式
dev: ## 启动开发模式
	@echo "启动开发服务器..."
	@echo "1. 文档服务器: http://localhost:3000"
	@echo "2. 桌面应用: 运行 'make dev-desktop'"
	@echo "3. 移动应用: 运行 'make dev-mobile'"
	make docs-serve

dev-desktop: ## 启动桌面应用开发模式
	cd desktop && npm run tauri dev

dev-mobile: ## 启动移动应用开发模式
	cd mobile && flutter run

# 测试
test: ## 运行所有测试
	@echo "运行 Rust 测试 (workspace, all features)..."
	cargo test --workspace --all-features
	@echo "运行桌面应用测试..."
	cd desktop && npm test
	@echo "运行移动应用测试..."
	cd mobile && flutter test
	@echo "测试完成!"

test-all: test ## 运行所有测试（别名）

test-rust: ## 运行 Rust 测试
	cargo test

test-desktop: ## 运行桌面应用测试
	cd desktop && npm test

test-mobile: ## 运行移动应用测试
	cd mobile && flutter test

# 代码检查
lint: ## 运行代码检查
	@echo "检查 Rust 代码 (workspace, all targets/features)..."
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "检查桌面应用代码..."
	cd desktop && npm run lint
	@echo "检查移动应用代码..."
	cd mobile && flutter analyze
	@echo "代码检查完成!"

lint-all: lint ## 运行所有代码检查（别名）

# 代码格式化
format: ## 格式化代码
	@echo "格式化 Rust 代码 (workspace)..."
	cargo fmt --all
	@echo "格式化桌面应用代码..."
	cd desktop && npm run format
	@echo "格式化移动应用代码..."
	cd mobile && dart format .
	@echo "代码格式化完成!"

format-all: format ## 格式化所有代码（别名）

# 清理
clean: ## 清理构建文件
	@echo "清理 Rust 构建文件..."
	cargo clean
	@echo "清理桌面应用构建文件..."
	cd desktop && rm -rf dist node_modules/.cache
	@echo "清理移动应用构建文件..."
	cd mobile && flutter clean
	@echo "清理文档构建文件..."
	rm -rf docs/book docs/dist
	@echo "清理完成!"

# 文档相关命令
docs: docs-serve ## 启动文档开发服务器

docs-serve: ## 启动文档开发服务器
	./scripts/build-docs.sh serve

docs-build: ## 构建文档
	./scripts/build-docs.sh build

docs-deploy: ## 部署文档到 GitHub Pages
	./scripts/build-docs.sh deploy

docs-clean: ## 清理文档构建文件
	./scripts/build-docs.sh clean

# 发布相关
release-patch: ## 发布补丁版本
	@echo "发布补丁版本..."
	@./scripts/release.sh patch

release-minor: ## 发布次要版本
	@echo "发布次要版本..."
	@./scripts/release.sh minor

release-major: ## 发布主要版本
	@echo "发布主要版本..."
	@./scripts/release.sh major

# 安全检查
security-audit: ## 运行安全审计
	@echo "运行 Rust 安全审计..."
	cargo audit
	@echo "运行 Node.js 安全审计..."
	cd desktop && npm audit
	@echo "安全审计完成!"

security-check: ## 运行完整安全检查（audit + deny）
	@echo "=== 运行 cargo-deny 供应链检查 ==="
	cargo deny check
	@echo ""
	@echo "=== 运行 cargo-audit 漏洞扫描 ==="
	cargo audit
	@echo ""
	@echo "=== 运行 npm audit ==="
	cd desktop && npm audit || true
	@echo ""
	@echo "安全检查完成!"

security-advisories: ## 仅检查已知漏洞
	@echo "检查 Rust 漏洞数据库..."
	cargo deny check advisories
	cargo audit
	@echo "漏洞检查完成!"

security-licenses: ## 检查许可证合规性
	@echo "检查依赖许可证..."
	cargo deny check licenses
	@echo "许可证检查完成!"

security-bans: ## 检查禁用的依赖
	@echo "检查禁用的依赖..."
	cargo deny check bans
	@echo "依赖检查完成!"

security-sources: ## 检查依赖来源
	@echo "检查依赖来源..."
	cargo deny check sources
	@echo "来源检查完成!"

# 性能测试
benchmark: ## 运行性能测试
	@echo "运行 Rust 性能测试..."
	cargo bench
	@echo "性能测试完成!"

# Docker 相关
docker-build: ## 构建 Docker 镜像
	docker build -t persona:latest .

docker-run: ## 运行 Docker 容器
	docker run -p 8080:8080 persona:latest

# 数据库相关
db-migrate: ## 运行数据库迁移
	@echo "运行数据库迁移..."
	cargo run --bin migrate

db-reset: ## 重置数据库
	@echo "重置数据库..."
	rm -f *.db *.db-*
	make db-migrate

# 开发工具
watch: ## 监听文件变化并自动重新构建
	cargo watch -x "build --release"

check-deps: ## 检查依赖更新
	@echo "检查 Rust 依赖更新..."
	cargo outdated
	@echo "检查 Node.js 依赖更新..."
	cd desktop && npm outdated
	@echo "检查 Flutter 依赖更新..."
	cd mobile && flutter pub outdated

# 生成文档
generate-docs: ## 生成 API 文档
	@echo "生成 Rust API 文档..."
	cargo doc --no-deps --open
	@echo "生成 TypeScript 文档..."
	cd desktop && npm run docs

# 国际化
i18n-extract: ## 提取国际化字符串
	@echo "提取国际化字符串..."
	cd desktop && npm run i18n:extract
	cd mobile && flutter gen-l10n

# 全面检查
check-all: lint test security-check ## 运行所有检查（包括安全检查）
	@echo "所有检查完成!"

# CI/CD 相关
ci: install lint test security-advisories ## CI 流水线（包括漏洞扫描）
	@echo "CI 流水线完成!"

cd: build docs-build ## CD 流水线
	@echo "CD 流水线完成!"
