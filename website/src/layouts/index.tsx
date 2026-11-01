import React from 'react';
import { Outlet, Link, useLocation } from 'umi';
import { Layout, Menu, Button, Space } from 'antd';
import { GithubOutlined, DownloadOutlined } from '@ant-design/icons';
import styles from './index.less';

const { Header, Content, Footer } = Layout;

const BasicLayout: React.FC = () => {
  const location = useLocation();

  const menuItems = [
    { key: '/', label: <Link to="/">首页</Link> },
    { key: '/features', label: <Link to="/features">功能特性</Link> },
    { key: '/download', label: <Link to="/download">下载</Link> },
    { key: '/docs', label: <Link to="/docs">文档</Link> },
    { key: '/pricing', label: <Link to="/pricing">定价</Link> },
  ];

  return (
    <Layout className={styles.layout}>
      <Header className={styles.header}>
        <div className={styles.headerContent}>
          <Link to="/" className={styles.logo}>
            <span className={styles.logoIcon}>🛡️</span>
            <span className={styles.logoText}>Persona</span>
          </Link>

          <Menu
            mode="horizontal"
            selectedKeys={[location.pathname]}
            items={menuItems}
            className={styles.menu}
          />

          <Space className={styles.actions}>
            <Button
              icon={<GithubOutlined />}
              href="https://github.com/persona-id/persona"
              target="_blank"
            >
              GitHub
            </Button>
            <Link to="/download" style={{ color: 'inherit' }}>
              <Button type="primary" icon={<DownloadOutlined />}>下载</Button>
            </Link>
          </Space>
        </div>
      </Header>

      <Content className={styles.content}>
        <Outlet />
      </Content>

      <Footer className={styles.footer}>
        <div className={styles.footerContent}>
          <div className={styles.footerSection}>
            <h4>产品</h4>
            <Link to="/features">功能特性</Link>
            <Link to="/download">下载</Link>
            <Link to="/pricing">定价</Link>
          </div>
          <div className={styles.footerSection}>
            <h4>开发者</h4>
            <Link to="/docs">文档</Link>
            <a href="https://github.com/persona-id/persona" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://github.com/persona-id/persona/issues" target="_blank" rel="noopener noreferrer">反馈</a>
          </div>
          <div className={styles.footerSection}>
            <h4>关于</h4>
            {/* 无对应路由且暂无正式文案：不制造 404，标注「即将上线」 */}
            <span className={styles.comingSoon}>安全性（即将上线）</span>
            <span className={styles.comingSoon}>隐私政策（即将上线）</span>
            <span className={styles.comingSoon}>使用条款（即将上线）</span>
          </div>
          <div className={styles.footerSection}>
            <h4>联系我们</h4>
            <a href="mailto:support@persona.id">support@persona.id</a>
            <a href="https://twitter.com/persona_id" target="_blank" rel="noopener noreferrer">Twitter</a>
          </div>
        </div>
        <div className={styles.footerBottom}>
          <p>© {new Date().getFullYear()} Persona. 开源软件，采用 MIT 许可证。</p>
        </div>
      </Footer>
    </Layout>
  );
};

export default BasicLayout;
