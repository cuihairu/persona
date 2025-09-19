// Persona 文档自定义脚本

(function() {
    'use strict';

    // 等待页面加载完成
    document.addEventListener('DOMContentLoaded', function() {
        initPersonaFeatures();
    });

    function initPersonaFeatures() {
        // 添加复制代码功能
        addCopyCodeButtons();
        
        // 添加目录展开/折叠功能
        addTocToggle();
        
        // 添加返回顶部按钮
        addBackToTop();
        
        // 添加主题切换增强
        enhanceThemeToggle();
        
        // 添加搜索增强
        enhanceSearch();
    }

    // 为代码块添加复制按钮
    function addCopyCodeButtons() {
        const codeBlocks = document.querySelectorAll('pre code');
        
        codeBlocks.forEach(function(codeBlock) {
            const pre = codeBlock.parentNode;
            const button = document.createElement('button');
            
            button.className = 'copy-code-button';
            button.textContent = '复制';
            button.setAttribute('aria-label', '复制代码');
            
            button.addEventListener('click', function() {
                const text = codeBlock.textContent;
                
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(function() {
                        showCopySuccess(button);
                    });
                } else {
                    // 降级方案
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showCopySuccess(button);
                }
            });
            
            pre.style.position = 'relative';
            pre.appendChild(button);
        });
    }

    function showCopySuccess(button) {
        const originalText = button.textContent;
        button.textContent = '已复制!';
        button.style.background = '#10b981';
        
        setTimeout(function() {
            button.textContent = originalText;
            button.style.background = '';
        }, 2000);
    }

    // 添加目录展开/折叠功能
    function addTocToggle() {
        const tocItems = document.querySelectorAll('.chapter-item');
        
        tocItems.forEach(function(item) {
            if (item.querySelector('.chapter-item')) {
                const link = item.querySelector('a');
                if (link) {
                    const toggle = document.createElement('span');
                    toggle.className = 'toc-toggle';
                    toggle.textContent = '▼';
                    toggle.style.cursor = 'pointer';
                    toggle.style.marginRight = '0.5rem';
                    
                    toggle.addEventListener('click', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        
                        const subItems = item.querySelectorAll('.chapter-item');
                        const isExpanded = item.classList.contains('expanded');
                        
                        if (isExpanded) {
                            item.classList.remove('expanded');
                            toggle.textContent = '▶';
                            subItems.forEach(function(subItem) {
                                subItem.style.display = 'none';
                            });
                        } else {
                            item.classList.add('expanded');
                            toggle.textContent = '▼';
                            subItems.forEach(function(subItem) {
                                subItem.style.display = 'block';
                            });
                        }
                    });
                    
                    link.insertBefore(toggle, link.firstChild);
                }
            }
        });
    }

    // 添加返回顶部按钮
    function addBackToTop() {
        const button = document.createElement('button');
        button.className = 'back-to-top';
        button.textContent = '↑';
        button.setAttribute('aria-label', '返回顶部');
        button.style.cssText = `
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 3rem;
            height: 3rem;
            border-radius: 50%;
            background: var(--persona-primary);
            color: white;
            border: none;
            cursor: pointer;
            font-size: 1.2rem;
            display: none;
            z-index: 1000;
            transition: all 0.3s ease;
        `;
        
        button.addEventListener('click', function() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
        
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                button.style.display = 'block';
            } else {
                button.style.display = 'none';
            }
        });
        
        document.body.appendChild(button);
    }

    // 增强主题切换
    function enhanceThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', function() {
                // 添加切换动画
                document.body.style.transition = 'background-color 0.3s ease, color 0.3s ease';
                
                setTimeout(function() {
                    document.body.style.transition = '';
                }, 300);
            });
        }
    }

    // 增强搜索功能
    function enhanceSearch() {
        const searchInput = document.getElementById('searchbar');
        if (searchInput) {
            // 添加搜索快捷键 (Ctrl/Cmd + K)
            document.addEventListener('keydown', function(e) {
                if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                    e.preventDefault();
                    searchInput.focus();
                }
            });
            
            // 添加搜索提示
            if (!searchInput.placeholder) {
                searchInput.placeholder = '搜索文档... (Ctrl+K)';
            }
        }
    }

    // 添加代码高亮增强
    function enhanceCodeHighlight() {
        // 为不同语言的代码块添加标签
        const codeBlocks = document.querySelectorAll('pre code[class*="language-"]');
        
        codeBlocks.forEach(function(codeBlock) {
            const className = codeBlock.className;
            const language = className.match(/language-(\w+)/);
            
            if (language) {
                const pre = codeBlock.parentNode;
                const label = document.createElement('div');
                label.className = 'code-language-label';
                label.textContent = language[1].toUpperCase();
                label.style.cssText = `
                    position: absolute;
                    top: 0.5rem;
                    right: 0.5rem;
                    background: rgba(0, 0, 0, 0.7);
                    color: white;
                    padding: 0.2rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.8rem;
                    font-weight: bold;
                `;
                
                pre.style.position = 'relative';
                pre.appendChild(label);
            }
        });
    }

    // 添加页面加载进度条
    function addLoadingProgress() {
        const progressBar = document.createElement('div');
        progressBar.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 0%;
            height: 3px;
            background: var(--persona-primary);
            z-index: 9999;
            transition: width 0.3s ease;
        `;
        
        document.body.appendChild(progressBar);
        
        // 模拟加载进度
        let progress = 0;
        const interval = setInterval(function() {
            progress += Math.random() * 30;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                setTimeout(function() {
                    progressBar.style.opacity = '0';
                    setTimeout(function() {
                        document.body.removeChild(progressBar);
                    }, 300);
                }, 500);
            }
            progressBar.style.width = progress + '%';
        }, 100);
    }

    // 添加打印优化
    function addPrintOptimization() {
        window.addEventListener('beforeprint', function() {
            // 展开所有折叠的内容
            const collapsedItems = document.querySelectorAll('.chapter-item:not(.expanded)');
            collapsedItems.forEach(function(item) {
                item.classList.add('expanded');
            });
        });
    }

    // CSS 样式注入
    const style = document.createElement('style');
    style.textContent = `
        .copy-code-button {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: var(--persona-primary);
            color: white;
            border: none;
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            font-size: 0.8rem;
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        pre:hover .copy-code-button {
            opacity: 1;
        }
        
        .copy-code-button:hover {
            background: var(--persona-secondary);
        }
        
        .toc-toggle {
            font-size: 0.8rem;
            color: var(--sidebar-fg);
            user-select: none;
        }
        
        .back-to-top:hover {
            background: var(--persona-secondary) !important;
            transform: translateY(-2px);
        }
        
        .code-language-label {
            user-select: none;
            pointer-events: none;
        }
    `;
    
    document.head.appendChild(style);

    // 初始化所有增强功能
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            enhanceCodeHighlight();
            addPrintOptimization();
        });
    } else {
        enhanceCodeHighlight();
        addPrintOptimization();
    }

})();