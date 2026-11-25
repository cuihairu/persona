#!/bin/bash

# Persona docs build script
# Builds and deploys the VitePress documentation

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging helpers
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v npm &> /dev/null; then
        log_error "npm 未安装，请先安装 Node.js / npm"
        exit 1
    fi
    
    log_success "依赖检查完成"
}

ensure_dependencies() {
    if [ ! -d "docs/node_modules/vitepress" ]; then
        log_info "安装 docs 依赖..."
        npm --prefix docs ci
    fi
}

# Clean old build files
clean_build() {
    log_info "清理旧的构建文件..."
    
    rm -rf docs/book docs/dist docs/.vitepress/dist docs/.vitepress/cache
    log_success "已清理文档构建目录"
}

# Build the docs
build_docs() {
    log_info "开始构建文档..."

    ensure_dependencies
    npm --prefix docs run build
    
    if [ $? -eq 0 ]; then
        log_success "文档构建成功"
    else
        log_error "文档构建失败"
        exit 1
    fi
    
}

# Validate the build output
validate_build() {
    log_info "验证构建结果..."
    
    if [ ! -d "docs/.vitepress/dist" ]; then
        log_error "构建目录不存在"
        exit 1
    fi
    
    if [ ! -f "docs/.vitepress/dist/index.html" ]; then
        log_error "主页文件不存在"
        exit 1
    fi
    
    # Check the build size
    book_size=$(du -sh docs/.vitepress/dist | cut -f1)
    log_info "构建文档大小: $book_size"
    
    log_success "构建结果验证通过"
}

# Start the dev server
serve_docs() {
    log_info "启动开发服务器..."

    ensure_dependencies
    npm --prefix docs run dev -- --port 3000 --open
}

# Deploy to GitHub Pages
deploy_github_pages() {
    log_info "部署到 GitHub Pages..."
    
    # Check that we are in a git repository
    if [ ! -d ".git" ]; then
        log_error "当前目录不是 git 仓库"
        exit 1
    fi
    
    # Check for uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        log_warning "存在未提交的更改，建议先提交"
    fi
    
    # Build the docs
    build_docs
    
    # Create the gh-pages branch if it does not exist
    if ! git show-ref --verify --quiet refs/heads/gh-pages; then
        log_info "创建 gh-pages 分支..."
        git checkout --orphan gh-pages
        git rm -rf .
        git commit --allow-empty -m "Initial gh-pages commit"
        git checkout main
    fi
    
    # Switch to the gh-pages branch
    git checkout gh-pages
    
    # Clean old files
    git rm -rf . 2>/dev/null || true
    
    # Copy the build output
    cp -r docs/.vitepress/dist/* .
    
    # Add the .nojekyll file
    touch .nojekyll
    
    # Commit the changes
    git add .
    git commit -m "Deploy docs: $(date)"
    
    # Push to the remote
    git push origin gh-pages
    
    # Switch back to the main branch
    git checkout main
    
    log_success "部署完成"
}

# Show help
show_help() {
    echo "Persona 文档构建脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  build     构建 VitePress 文档"
    echo "  serve     启动 VitePress 开发服务器"
    echo "  clean     清理构建文件"
    echo "  deploy    部署到 GitHub Pages"
    echo "  check     检查依赖"
    echo "  help      显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 build          # 构建文档"
    echo "  $0 serve          # 启动开发服务器"
    echo "  $0 deploy         # 部署到 GitHub Pages"
}

# Main function
main() {
    case "${1:-build}" in
        "build")
            check_dependencies
            clean_build
            build_docs
            validate_build
            ;;
        "serve")
            check_dependencies
            serve_docs
            ;;
        "clean")
            clean_build
            ;;
        "deploy")
            check_dependencies
            deploy_github_pages
            ;;
        "check")
            check_dependencies
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run the main function
main "$@"
