// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="index.html">介绍</a></li><li class="chapter-item expanded affix "><li class="spacer"></li><li class="chapter-item expanded affix "><li class="part-title">项目概述</li><li class="chapter-item expanded "><a href="overview/introduction.html"><strong aria-hidden="true">1.</strong> 项目简介</a></li><li class="chapter-item expanded "><a href="overview/features.html"><strong aria-hidden="true">2.</strong> 核心功能</a></li><li class="chapter-item expanded "><a href="overview/architecture.html"><strong aria-hidden="true">3.</strong> 技术架构</a></li><li class="chapter-item expanded "><a href="overview/security.html"><strong aria-hidden="true">4.</strong> 安全特性</a></li><li class="chapter-item expanded affix "><li class="part-title">需求分析</li><li class="chapter-item expanded "><a href="analysis/scenarios.html"><strong aria-hidden="true">5.</strong> 场景分析</a></li><li class="chapter-item expanded "><a href="analysis/security-requirements.html"><strong aria-hidden="true">6.</strong> 安全需求</a></li><li class="chapter-item expanded "><a href="analysis/user-requirements.html"><strong aria-hidden="true">7.</strong> 用户需求</a></li><li class="chapter-item expanded "><a href="analysis/technical-requirements.html"><strong aria-hidden="true">8.</strong> 技术需求</a></li><li class="chapter-item expanded affix "><li class="part-title">系统设计</li><li class="chapter-item expanded "><a href="design/architecture.html"><strong aria-hidden="true">9.</strong> 整体架构</a></li><li class="chapter-item expanded "><a href="design/data-model.html"><strong aria-hidden="true">10.</strong> 数据模型</a></li><li class="chapter-item expanded "><a href="design/api.html"><strong aria-hidden="true">11.</strong> API 设计</a></li><li class="chapter-item expanded "><a href="design/security.html"><strong aria-hidden="true">12.</strong> 安全设计</a></li><li class="chapter-item expanded "><a href="design/ui-ux.html"><strong aria-hidden="true">13.</strong> UI/UX 设计</a></li><li class="chapter-item expanded affix "><li class="part-title">开发指南</li><li class="chapter-item expanded "><a href="development/setup.html"><strong aria-hidden="true">14.</strong> 环境搭建</a></li><li class="chapter-item expanded "><a href="development/structure.html"><strong aria-hidden="true">15.</strong> 项目结构</a></li><li class="chapter-item expanded "><a href="development/coding-standards.html"><strong aria-hidden="true">16.</strong> 编码规范</a></li><li class="chapter-item expanded "><a href="development/testing.html"><strong aria-hidden="true">17.</strong> 测试指南</a></li><li class="chapter-item expanded "><a href="development/deployment.html"><strong aria-hidden="true">18.</strong> 部署指南</a></li><li class="chapter-item expanded affix "><li class="part-title">API 文档</li><li class="chapter-item expanded "><a href="api/authentication.html"><strong aria-hidden="true">19.</strong> 认证 API</a></li><li class="chapter-item expanded "><a href="api/identity.html"><strong aria-hidden="true">20.</strong> 身份管理 API</a></li><li class="chapter-item expanded "><a href="api/sync.html"><strong aria-hidden="true">21.</strong> 数据同步 API</a></li><li class="chapter-item expanded "><a href="api/security.html"><strong aria-hidden="true">22.</strong> 安全 API</a></li><li class="chapter-item expanded affix "><li class="part-title">用户手册</li><li class="chapter-item expanded "><a href="user/quick-start.html"><strong aria-hidden="true">23.</strong> 快速开始</a></li><li class="chapter-item expanded "><a href="user/desktop.html"><strong aria-hidden="true">24.</strong> 桌面应用</a></li><li class="chapter-item expanded "><a href="user/mobile.html"><strong aria-hidden="true">25.</strong> 移动应用</a></li><li class="chapter-item expanded "><a href="user/faq.html"><strong aria-hidden="true">26.</strong> 常见问题</a></li><li class="chapter-item expanded "><a href="user/troubleshooting.html"><strong aria-hidden="true">27.</strong> 故障排除</a></li><li class="chapter-item expanded affix "><li class="part-title">贡献指南</li><li class="chapter-item expanded "><a href="contributing/how-to-contribute.html"><strong aria-hidden="true">28.</strong> 如何贡献</a></li><li class="chapter-item expanded "><a href="contributing/code-review.html"><strong aria-hidden="true">29.</strong> 代码审查</a></li><li class="chapter-item expanded "><a href="contributing/release-process.html"><strong aria-hidden="true">30.</strong> 发布流程</a></li><li class="chapter-item expanded affix "><li class="spacer"></li><li class="chapter-item expanded affix "><a href="appendix/index.html">附录</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
