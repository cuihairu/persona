#!/bin/bash

# Persona 文档构建脚本
# 用于构建和部署 mdbook 文档

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
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

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v mdbook &> /dev/null; then
        log_error "mdbook 未安装，请先安装 mdbook"
        log_info "安装命令: cargo install mdbook"
        exit 1
    fi
    
    log_success "依赖检查完成"
}

# 清理旧的构建文件
clean_build() {
    log_info "清理旧的构建文件..."
    
    if [ -d "docs/book" ]; then
        rm -rf docs/book
        log_success "已清理 docs/book 目录"
    fi
    
    if [ -d "docs/dist" ]; then
        rm -rf docs/dist
        log_success "已清理 docs/dist 目录"
    fi
}

# 构建文档
build_docs() {
    log_info "开始构建文档..."
    
    cd docs
    
    # 构建 mdbook
    mdbook build
    
    if [ $? -eq 0 ]; then
        log_success "文档构建成功"
    else
        log_error "文档构建失败"
        exit 1
    fi
    
    cd ..
}

# 验证构建结果
validate_build() {
    log_info "验证构建结果..."
    
    if [ ! -d "docs/book" ]; then
        log_error "构建目录不存在"
        exit 1
    fi
    
    if [ ! -f "docs/book/index.html" ]; then
        log_error "主页文件不存在"
        exit 1
    fi
    
    # 检查文件大小
    book_size=$(du -sh docs/book | cut -f1)
    log_info "构建文档大小: $book_size"
    
    log_success "构建结果验证通过"
}

# 启动开发服务器
serve_docs() {
    log_info "启动开发服务器..."
    
    cd docs
    mdbook serve --open --port 3000
}

# 部署到 GitHub Pages
deploy_github_pages() {
    log_info "部署到 GitHub Pages..."
    
    # 检查是否在 git 仓库中
    if [ ! -d ".git" ]; then
        log_error "当前目录不是 git 仓库"
        exit 1
    fi
    
    # 检查是否有未提交的更改
    if [ -n "$(git status --porcelain)" ]; then
        log_warning "存在未提交的更改，建议先提交"
    fi
    
    # 构建文档
    build_docs
    
    # 创建 gh-pages 分支（如果不存在）
    if ! git show-ref --verify --quiet refs/heads/gh-pages; then
        log_info "创建 gh-pages 分支..."
        git checkout --orphan gh-pages
        git rm -rf .
        git commit --allow-empty -m "Initial gh-pages commit"
        git checkout main
    fi
    
    # 切换到 gh-pages 分支
    git checkout gh-pages
    
    # 清理旧文件
    git rm -rf . 2>/dev/null || true
    
    # 复制构建文件
    cp -r docs/book/* .
    
    # 添加 .nojekyll 文件
    touch .nojekyll
    
    # 提交更改
    git add .
    git commit -m "Deploy docs: $(date)"
    
    # 推送到远程
    git push origin gh-pages
    
    # 切换回主分支
    git checkout main
    
    log_success "部署完成"
}

# 显示帮助信息
show_help() {
    echo "Persona 文档构建脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  build     构建文档"
    echo "  serve     启动开发服务器"
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

# 主函数
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

# 执行主函数
main "$@"