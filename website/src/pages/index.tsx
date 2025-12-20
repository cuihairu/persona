import React from 'react';
import { Link } from 'umi';
import { Button, Space, Card, Row, Col, Typography } from 'antd';
import {
  SafetyCertificateOutlined,
  KeyOutlined,
  WalletOutlined,
  ApiOutlined,
  LockOutlined,
  CloudSyncOutlined,
  GlobalOutlined,
  ThunderboltOutlined,
  GithubOutlined,
  AppleOutlined,
  WindowsOutlined,
  LinuxOutlined,
} from '@ant-design/icons';
import styles from './index.less';

const { Title, Paragraph } = Typography;

const IndexPage: React.FC = () => {
  const features = [
    {
      icon: <LockOutlined />,
      title: '密码管理',
      description: '安全存储所有密码和敏感信息，使用军事级加密保护您的数据。',
    },
    {
      icon: <KeyOutlined />,
      title: 'SSH Agent',
      description: '内置 SSH 密钥管理和代理，支持 GitHub、GitLab 等开发工作流。',
    },
    {
      icon: <WalletOutlined />,
      title: '数字钱包',
      description: '安全管理加密货币钱包，支持 BTC、ETH、Solana 等多链资产。',
    },
    {
      icon: <ApiOutlined />,
      title: 'TOTP 验证',
      description: '内置双因素认证，保护您的账户免受未授权访问。',
    },
    {
      icon: <CloudSyncOutlined />,
      title: '跨设备同步',
      description: '端到端加密同步，您的数据在所有设备上安全可用。',
    },
    {
      icon: <GlobalOutlined />,
      title: '浏览器扩展',
      description: '智能自动填充，支持 Chrome、Firefox、Safari 等主流浏览器。',
    },
  ];

  const stats = [
    { number: '256-bit', label: 'AES 加密' },
    { number: '100%', label: '开源代码' },
    { number: '0', label: '数据泄露' },
    { number: '∞', label: '存储空间' },
  ];

  return (
    <div className={styles.page}>
      {/* Hero Section */}
      <section className={styles.hero}>
        <div className={styles.heroContent}>
          <div className={styles.heroText}>
            <div className={styles.badge}>
              <SafetyCertificateOutlined /> 开源 · 安全 · 隐私优先
            </div>
            <Title level={1} className={styles.heroTitle}>
              您的数字身份
              <span className={styles.gradient}>守护者</span>
            </Title>
            <Paragraph className={styles.heroDesc}>
              Persona 是一款现代化的开源密码管理器，专为开发者打造。
              集成 SSH Agent、数字钱包和 TOTP 验证，一站式保护您的数字资产。
            </Paragraph>
            <Space size="large" className={styles.heroActions}>
              <Button type="primary" size="large" icon={<ThunderboltOutlined />}>
                <Link to="/download" style={{ color: 'inherit' }}>免费下载</Link>
              </Button>
              <Button size="large" icon={<GithubOutlined />} href="https://github.com/persona-id/persona" target="_blank">
                查看源码
              </Button>
            </Space>
            <div className={styles.platforms}>
              <span>支持平台：</span>
              <AppleOutlined title="macOS" />
              <WindowsOutlined title="Windows" />
              <LinuxOutlined title="Linux" />
            </div>
          </div>
          <div className={styles.heroVisual}>
            <div className={styles.mockup}>
              <div className={styles.mockupHeader}>
                <span className={styles.dot} style={{ background: '#ff5f57' }} />
                <span className={styles.dot} style={{ background: '#febc2e' }} />
                <span className={styles.dot} style={{ background: '#28c840' }} />
              </div>
              <div className={styles.mockupContent}>
                <div className={styles.vaultItem}>
                  <div className={styles.vaultIcon}>🔐</div>
                  <div className={styles.vaultInfo}>
                    <div className={styles.vaultTitle}>GitHub</div>
                    <div className={styles.vaultSubtitle}>dev@example.com</div>
                  </div>
                </div>
                <div className={styles.vaultItem}>
                  <div className={styles.vaultIcon}>🔑</div>
                  <div className={styles.vaultInfo}>
                    <div className={styles.vaultTitle}>SSH Key - ed25519</div>
                    <div className={styles.vaultSubtitle}>生产服务器</div>
                  </div>
                </div>
                <div className={styles.vaultItem}>
                  <div className={styles.vaultIcon}>💰</div>
                  <div className={styles.vaultInfo}>
                    <div className={styles.vaultTitle}>ETH Wallet</div>
                    <div className={styles.vaultSubtitle}>0x1234...5678</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className={styles.stats}>
        <div className={styles.statsContent}>
          {stats.map((stat, index) => (
            <div key={index} className={styles.statItem}>
              <div className={styles.statNumber}>{stat.number}</div>
              <div className={styles.statLabel}>{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features Section */}
      <section className={styles.features}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>
            为开发者打造的安全工具
          </Title>
          <Paragraph className={styles.sectionDesc}>
            不仅仅是密码管理器，Persona 是您数字生活的全方位守护者
          </Paragraph>
          <Row gutter={[24, 24]} className={styles.featureGrid}>
            {features.map((feature, index) => (
              <Col xs={24} sm={12} lg={8} key={index}>
                <Card className={styles.featureCard} hoverable>
                  <div className={styles.featureIcon}>{feature.icon}</div>
                  <Title level={4} className={styles.featureTitle}>{feature.title}</Title>
                  <Paragraph className={styles.featureDesc}>{feature.description}</Paragraph>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* SSH Agent Highlight */}
      <section className={styles.highlight}>
        <div className={styles.highlightContent}>
          <div className={styles.highlightText}>
            <Title level={2}>SSH Agent 集成</Title>
            <Paragraph>
              告别繁琐的密钥管理。Persona 内置 SSH Agent 可以安全存储和管理您的所有 SSH 密钥。
            </Paragraph>
            <ul className={styles.highlightList}>
              <li>✓ 支持 ed25519、RSA、ECDSA 密钥</li>
              <li>✓ 生物识别解锁（Touch ID / Windows Hello）</li>
              <li>✓ 细粒度访问策略（按主机、时间限制）</li>
              <li>✓ 完整的审计日志</li>
            </ul>
            <Button type="primary">
              <Link to="/features" style={{ color: 'inherit' }}>了解更多</Link>
            </Button>
          </div>
          <div className={styles.highlightCode}>
            <pre>
              <code>{`# 启动 Persona SSH Agent
$ persona ssh start-agent

# 导入现有密钥
$ persona ssh import ~/.ssh/id_ed25519

# 使用 Persona Agent 连接 GitHub
$ SSH_AUTH_SOCK=$(persona ssh socket) \\
  ssh -T git@github.com

> Hi developer! You've successfully authenticated!`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Wallet Highlight */}
      <section className={styles.highlightAlt}>
        <div className={styles.highlightContent}>
          <div className={styles.highlightCode}>
            <pre>
              <code>{`# 创建新的 HD 钱包
$ persona wallet create --chain eth

# 派生地址
$ persona wallet derive --chain eth --account 0

# 签名交易
$ persona wallet sign --chain eth \\
  --to 0x... --value 0.1 --data 0x...

> Transaction signed successfully!
> Hash: 0x7f8c...3d2a`}</code>
            </pre>
          </div>
          <div className={styles.highlightText}>
            <Title level={2}>数字钱包支持</Title>
            <Paragraph>
              安全管理您的加密资产。支持 BIP-32/39/44 标准，兼容所有主流钱包。
            </Paragraph>
            <ul className={styles.highlightList}>
              <li>✓ 多链支持（BTC、ETH、Solana）</li>
              <li>✓ HD 钱包派生</li>
              <li>✓ 硬件钱包级安全</li>
              <li>✓ 交易签名确认</li>
            </ul>
            <Button type="primary">
              <Link to="/features" style={{ color: 'inherit' }}>了解更多</Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Open Source Section */}
      <section className={styles.openSource}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>
            100% 开源，永久免费
          </Title>
          <Paragraph className={styles.sectionDesc}>
            我们相信安全软件应该是透明的。Persona 的每一行代码都在 GitHub 上公开，
            欢迎社区审计、贡献和改进。
          </Paragraph>
          <Space size="large">
            <Button type="primary" size="large" icon={<GithubOutlined />} href="https://github.com/persona-id/persona" target="_blank">
              GitHub 仓库
            </Button>
            <Button size="large">
              <Link to="/docs" style={{ color: 'inherit' }}>查看文档</Link>
            </Button>
          </Space>
        </div>
      </section>

      {/* CTA Section */}
      <section className={styles.cta}>
        <div className={styles.ctaContent}>
          <Title level={2} className={styles.ctaTitle}>
            准备好保护您的数字身份了吗？
          </Title>
          <Paragraph className={styles.ctaDesc}>
            下载 Persona，开始您的安全之旅。完全免费，无需注册。
          </Paragraph>
          <Button type="primary" size="large">
            <Link to="/download" style={{ color: 'inherit' }}>立即下载</Link>
          </Button>
        </div>
      </section>
    </div>
  );
};

export default IndexPage;
