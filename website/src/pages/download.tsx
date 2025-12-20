import React, { useState, useEffect } from 'react';
import { Typography, Card, Row, Col, Button, Tabs, Space, Alert } from 'antd';
import {
  AppleOutlined,
  WindowsOutlined,
  LinuxOutlined,
  ChromeOutlined,
  GithubOutlined,
  DownloadOutlined,
  CheckCircleOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import styles from './download.less';

const { Title, Paragraph, Text } = Typography;

type Platform = 'macos' | 'windows' | 'linux';

const DownloadPage: React.FC = () => {
  const [currentPlatform, setCurrentPlatform] = useState<Platform>('macos');

  useEffect(() => {
    // Detect platform
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('mac')) {
      setCurrentPlatform('macos');
    } else if (userAgent.includes('win')) {
      setCurrentPlatform('windows');
    } else if (userAgent.includes('linux')) {
      setCurrentPlatform('linux');
    }
  }, []);

  const version = '0.1.0';

  const downloads: Record<Platform, { name: string; icon: React.ReactNode; files: { label: string; filename: string; size: string }[] }> = {
    macos: {
      name: 'macOS',
      icon: <AppleOutlined />,
      files: [
        { label: 'Universal (Intel + Apple Silicon)', filename: `Persona-${version}-universal.dmg`, size: '25 MB' },
        { label: 'Apple Silicon (M1/M2/M3)', filename: `Persona-${version}-aarch64.dmg`, size: '12 MB' },
        { label: 'Intel', filename: `Persona-${version}-x64.dmg`, size: '13 MB' },
      ],
    },
    windows: {
      name: 'Windows',
      icon: <WindowsOutlined />,
      files: [
        { label: 'Installer (x64)', filename: `Persona-${version}-x64.msi`, size: '18 MB' },
        { label: 'Portable (x64)', filename: `Persona-${version}-x64.zip`, size: '20 MB' },
        { label: 'ARM64', filename: `Persona-${version}-arm64.msi`, size: '17 MB' },
      ],
    },
    linux: {
      name: 'Linux',
      icon: <LinuxOutlined />,
      files: [
        { label: 'AppImage (x64)', filename: `Persona-${version}-x86_64.AppImage`, size: '22 MB' },
        { label: 'Debian/Ubuntu (.deb)', filename: `persona_${version}_amd64.deb`, size: '15 MB' },
        { label: 'Fedora/RHEL (.rpm)', filename: `persona-${version}-1.x86_64.rpm`, size: '15 MB' },
        { label: 'Arch Linux (AUR)', filename: 'persona-bin', size: '-' },
      ],
    },
  };

  const browserExtensions = [
    {
      name: 'Chrome',
      icon: <ChromeOutlined />,
      url: '#',
      status: '开发中',
    },
    {
      name: 'Firefox',
      icon: <GlobalOutlined />,
      url: '#',
      status: '开发中',
    },
    {
      name: 'Safari',
      icon: <AppleOutlined />,
      url: '#',
      status: '开发中',
    },
    {
      name: 'Edge',
      icon: <WindowsOutlined />,
      url: '#',
      status: '开发中',
    },
  ];

  const requirements = {
    macos: ['macOS 10.15 (Catalina) 或更高版本', 'Apple Silicon 或 Intel 处理器'],
    windows: ['Windows 10 (1809) 或更高版本', 'x64 或 ARM64 处理器'],
    linux: ['glibc 2.31+ (Ubuntu 20.04+, Debian 11+, Fedora 33+)', 'X11 或 Wayland'],
  };

  const platformTabs = [
    { key: 'macos', label: <><AppleOutlined /> macOS</>, icon: <AppleOutlined /> },
    { key: 'windows', label: <><WindowsOutlined /> Windows</>, icon: <WindowsOutlined /> },
    { key: 'linux', label: <><LinuxOutlined /> Linux</>, icon: <LinuxOutlined /> },
  ];

  return (
    <div className={styles.page}>
      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroContent}>
          <Title level={1}>下载 Persona</Title>
          <Paragraph className={styles.heroDesc}>
            免费下载，永久免费。支持 macOS、Windows 和 Linux。
          </Paragraph>
          <div className={styles.versionBadge}>
            <CheckCircleOutlined /> 当前版本: v{version}
          </div>
        </div>
      </section>

      {/* Main Download */}
      <section className={styles.mainDownload}>
        <div className={styles.sectionContent}>
          <Tabs
            activeKey={currentPlatform}
            onChange={(key) => setCurrentPlatform(key as Platform)}
            items={platformTabs}
            centered
            size="large"
            className={styles.platformTabs}
          />

          <Card className={styles.downloadCard}>
            <div className={styles.downloadHeader}>
              <div className={styles.platformIcon}>
                {downloads[currentPlatform].icon}
              </div>
              <div>
                <Title level={3}>{downloads[currentPlatform].name}</Title>
                <Text type="secondary">选择适合您系统的版本</Text>
              </div>
            </div>

            <div className={styles.downloadList}>
              {downloads[currentPlatform].files.map((file, index) => (
                <div key={index} className={styles.downloadItem}>
                  <div className={styles.downloadInfo}>
                    <div className={styles.downloadLabel}>{file.label}</div>
                    <div className={styles.downloadMeta}>
                      <Text type="secondary">{file.filename}</Text>
                      {file.size !== '-' && <Text type="secondary"> · {file.size}</Text>}
                    </div>
                  </div>
                  <Button type="primary" icon={<DownloadOutlined />} size="large">
                    下载
                  </Button>
                </div>
              ))}
            </div>

            <div className={styles.requirements}>
              <Title level={5}>系统要求</Title>
              <ul>
                {requirements[currentPlatform].map((req, index) => (
                  <li key={index}>{req}</li>
                ))}
              </ul>
            </div>
          </Card>
        </div>
      </section>

      {/* CLI Installation */}
      <section className={styles.cliSection}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>
            <CodeOutlined /> 命令行安装
          </Title>
          <Paragraph className={styles.sectionDesc}>
            使用包管理器快速安装 Persona CLI
          </Paragraph>

          <Row gutter={[24, 24]}>
            <Col xs={24} md={8}>
              <Card className={styles.cliCard}>
                <Title level={4}><AppleOutlined /> macOS (Homebrew)</Title>
                <div className={styles.cliCode}>
                  <code>brew install persona-id/tap/persona</code>
                </div>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card className={styles.cliCard}>
                <Title level={4}><WindowsOutlined /> Windows (Scoop)</Title>
                <div className={styles.cliCode}>
                  <code>scoop bucket add persona https://github.com/persona-id/scoop-bucket</code>
                  <code>scoop install persona</code>
                </div>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card className={styles.cliCard}>
                <Title level={4}><CodeOutlined /> Cargo (Rust)</Title>
                <div className={styles.cliCode}>
                  <code>cargo install persona-cli</code>
                </div>
              </Card>
            </Col>
          </Row>
        </div>
      </section>

      {/* Browser Extensions */}
      <section className={styles.browserSection}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>浏览器扩展</Title>
          <Paragraph className={styles.sectionDesc}>
            安装浏览器扩展，实现自动填充功能
          </Paragraph>

          <Alert
            message="浏览器扩展正在开发中"
            description="Chrome 扩展预计将在下一个版本发布，敬请期待！"
            type="info"
            showIcon
            className={styles.alert}
          />

          <Row gutter={[24, 24]}>
            {browserExtensions.map((ext, index) => (
              <Col xs={12} sm={6} key={index}>
                <Card className={styles.browserCard}>
                  <div className={styles.browserIcon}>{ext.icon}</div>
                  <Title level={5}>{ext.name}</Title>
                  <Text type="secondary">{ext.status}</Text>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* Source Code */}
      <section className={styles.sourceSection}>
        <div className={styles.sectionContent}>
          <Card className={styles.sourceCard}>
            <Row gutter={[40, 24]} align="middle">
              <Col xs={24} md={16}>
                <Title level={3}>从源码构建</Title>
                <Paragraph>
                  Persona 是完全开源的。您可以从 GitHub 获取源代码，自行审计和构建。
                </Paragraph>
                <div className={styles.cliCode}>
                  <code>git clone https://github.com/persona-id/persona.git</code>
                  <code>cd persona && make build</code>
                </div>
              </Col>
              <Col xs={24} md={8} className={styles.sourceActions}>
                <Space direction="vertical" size="middle">
                  <Button type="primary" icon={<GithubOutlined />} size="large" block href="https://github.com/persona-id/persona" target="_blank">
                    查看源码
                  </Button>
                  <Button icon={<DownloadOutlined />} size="large" block href="https://github.com/persona-id/persona/releases" target="_blank">
                    所有版本
                  </Button>
                </Space>
              </Col>
            </Row>
          </Card>
        </div>
      </section>
    </div>
  );
};

// Helper component for Firefox icon
const GlobalOutlined = () => (
  <span role="img" aria-label="firefox" className="anticon">
    🦊
  </span>
);

export default DownloadPage;
