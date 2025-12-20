import React from 'react';
import { Typography, Card, Row, Col, Tabs } from 'antd';
import {
  LockOutlined,
  KeyOutlined,
  WalletOutlined,
  ApiOutlined,
  SafetyCertificateOutlined,
  CloudSyncOutlined,
  GlobalOutlined,
  EyeInvisibleOutlined,
  ClockCircleOutlined,
  TeamOutlined,
  MobileOutlined,
  DesktopOutlined,
  CodeOutlined,
  AuditOutlined,
  ThunderboltOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import styles from './features.less';

const { Title, Paragraph } = Typography;

const FeaturesPage: React.FC = () => {
  const passwordFeatures = [
    {
      icon: <LockOutlined />,
      title: '军事级加密',
      description: '使用 AES-256 加密所有数据，密钥派生采用 Argon2id 算法。',
    },
    {
      icon: <ThunderboltOutlined />,
      title: '智能自动填充',
      description: '浏览器扩展自动检测登录表单，一键填充用户名和密码。',
    },
    {
      icon: <EyeInvisibleOutlined />,
      title: '密码生成器',
      description: '生成强随机密码，支持自定义长度、字符集和易读模式。',
    },
    {
      icon: <ClockCircleOutlined />,
      title: '自动锁定',
      description: '可配置的自动锁定时间，确保离开时数据安全。',
    },
    {
      icon: <AuditOutlined />,
      title: '安全审计',
      description: '检测弱密码、重复密码和泄露密码，提供安全评分。',
    },
    {
      icon: <TeamOutlined />,
      title: '多身份管理',
      description: '支持多个身份配置（工作/个人），轻松切换。',
    },
  ];

  const sshFeatures = [
    {
      icon: <KeyOutlined />,
      title: '密钥管理',
      description: '安全存储 ed25519、RSA、ECDSA 密钥，支持导入导出。',
    },
    {
      icon: <SafetyCertificateOutlined />,
      title: '生物识别',
      description: '支持 Touch ID / Windows Hello 解锁密钥。',
    },
    {
      icon: <SettingOutlined />,
      title: '访问策略',
      description: '细粒度的主机白名单、时间限制、使用次数配置。',
    },
    {
      icon: <AuditOutlined />,
      title: '审计日志',
      description: '完整记录每次密钥使用，支持日志导出和分析。',
    },
    {
      icon: <CodeOutlined />,
      title: 'Git 集成',
      description: '无缝集成 GitHub、GitLab、Bitbucket 等代码托管平台。',
    },
    {
      icon: <MobileOutlined />,
      title: '跨平台',
      description: 'macOS、Windows、Linux 全平台支持。',
    },
  ];

  const walletFeatures = [
    {
      icon: <WalletOutlined />,
      title: 'HD 钱包',
      description: '支持 BIP-32/39/44 标准，从助记词派生无限地址。',
    },
    {
      icon: <GlobalOutlined />,
      title: '多链支持',
      description: '支持 Bitcoin、Ethereum、Solana 等主流公链。',
    },
    {
      icon: <SafetyCertificateOutlined />,
      title: '硬件级安全',
      description: '私钥永不离开本地，签名确认保护资产安全。',
    },
    {
      icon: <ApiOutlined />,
      title: '交易签名',
      description: '支持 PSBT (BTC)、EIP-1559 (ETH)、SPL (Solana) 签名。',
    },
    {
      icon: <EyeInvisibleOutlined />,
      title: '观察钱包',
      description: '添加只读地址追踪余额，不暴露私钥。',
    },
    {
      icon: <AuditOutlined />,
      title: '交易历史',
      description: '完整的签名记录和交易审计日志。',
    },
  ];

  const platformFeatures = [
    {
      icon: <DesktopOutlined />,
      title: '桌面应用',
      description: '基于 Tauri 构建的原生桌面应用，轻量高效。',
      platforms: ['macOS', 'Windows', 'Linux'],
    },
    {
      icon: <MobileOutlined />,
      title: '移动应用',
      description: '原生 iOS 和 Android 应用（开发中）。',
      platforms: ['iOS', 'Android'],
    },
    {
      icon: <GlobalOutlined />,
      title: '浏览器扩展',
      description: '支持所有主流浏览器的自动填充扩展。',
      platforms: ['Chrome', 'Firefox', 'Safari', 'Edge'],
    },
    {
      icon: <CodeOutlined />,
      title: 'CLI 工具',
      description: '功能完整的命令行工具，支持脚本自动化。',
      platforms: ['Shell', 'CI/CD'],
    },
  ];

  const securityFeatures = [
    {
      title: '端到端加密',
      description: '所有数据在本地加密后再同步，服务器永远无法读取您的明文数据。',
    },
    {
      title: '零知识架构',
      description: '即使是 Persona 团队也无法访问您的数据，您的主密码永远不会离开设备。',
    },
    {
      title: '开源审计',
      description: '代码完全开源，接受社区审计。使用经过验证的加密库，不重复造轮子。',
    },
    {
      title: '本地优先',
      description: '数据默认存储在本地，同步为可选功能。完全离线也能正常使用。',
    },
  ];

  const tabItems = [
    {
      key: 'password',
      label: '密码管理',
      children: (
        <Row gutter={[24, 24]}>
          {passwordFeatures.map((feature, index) => (
            <Col xs={24} sm={12} lg={8} key={index}>
              <Card className={styles.featureCard}>
                <div className={styles.featureIcon}>{feature.icon}</div>
                <Title level={4}>{feature.title}</Title>
                <Paragraph className={styles.featureDesc}>{feature.description}</Paragraph>
              </Card>
            </Col>
          ))}
        </Row>
      ),
    },
    {
      key: 'ssh',
      label: 'SSH Agent',
      children: (
        <Row gutter={[24, 24]}>
          {sshFeatures.map((feature, index) => (
            <Col xs={24} sm={12} lg={8} key={index}>
              <Card className={styles.featureCard}>
                <div className={styles.featureIcon}>{feature.icon}</div>
                <Title level={4}>{feature.title}</Title>
                <Paragraph className={styles.featureDesc}>{feature.description}</Paragraph>
              </Card>
            </Col>
          ))}
        </Row>
      ),
    },
    {
      key: 'wallet',
      label: '数字钱包',
      children: (
        <Row gutter={[24, 24]}>
          {walletFeatures.map((feature, index) => (
            <Col xs={24} sm={12} lg={8} key={index}>
              <Card className={styles.featureCard}>
                <div className={styles.featureIcon}>{feature.icon}</div>
                <Title level={4}>{feature.title}</Title>
                <Paragraph className={styles.featureDesc}>{feature.description}</Paragraph>
              </Card>
            </Col>
          ))}
        </Row>
      ),
    },
  ];

  return (
    <div className={styles.page}>
      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroContent}>
          <Title level={1}>功能特性</Title>
          <Paragraph className={styles.heroDesc}>
            Persona 提供全方位的数字身份保护，从密码管理到 SSH 密钥，再到加密钱包，
            一站式解决您的安全需求。
          </Paragraph>
        </div>
      </section>

      {/* Feature Tabs */}
      <section className={styles.featureTabs}>
        <div className={styles.sectionContent}>
          <Tabs
            items={tabItems}
            centered
            size="large"
            className={styles.tabs}
          />
        </div>
      </section>

      {/* Platform Support */}
      <section className={styles.platforms}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>全平台支持</Title>
          <Paragraph className={styles.sectionDesc}>
            无论您使用什么设备，Persona 都能为您提供一致的体验
          </Paragraph>
          <Row gutter={[24, 24]}>
            {platformFeatures.map((feature, index) => (
              <Col xs={24} sm={12} lg={6} key={index}>
                <Card className={styles.platformCard}>
                  <div className={styles.platformIcon}>{feature.icon}</div>
                  <Title level={4}>{feature.title}</Title>
                  <Paragraph className={styles.platformDesc}>{feature.description}</Paragraph>
                  <div className={styles.platformTags}>
                    {feature.platforms.map((platform, i) => (
                      <span key={i} className={styles.platformTag}>{platform}</span>
                    ))}
                  </div>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* Security */}
      <section className={styles.security}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>安全至上</Title>
          <Paragraph className={styles.sectionDesc}>
            安全不是功能，而是我们的核心设计理念
          </Paragraph>
          <Row gutter={[40, 40]}>
            {securityFeatures.map((feature, index) => (
              <Col xs={24} md={12} key={index}>
                <div className={styles.securityItem}>
                  <div className={styles.securityNumber}>{String(index + 1).padStart(2, '0')}</div>
                  <div className={styles.securityText}>
                    <Title level={4}>{feature.title}</Title>
                    <Paragraph>{feature.description}</Paragraph>
                  </div>
                </div>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* CLI Preview */}
      <section className={styles.cliPreview}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.sectionTitle}>强大的 CLI 工具</Title>
          <Paragraph className={styles.sectionDesc}>
            为开发者设计的命令行界面，支持脚本自动化和 CI/CD 集成
          </Paragraph>
          <div className={styles.cliCode}>
            <pre>
              <code>{`# 身份管理
$ persona identity list
$ persona identity switch work

# 凭证操作
$ persona credential add --name github --type login
$ persona credential list --tag work
$ persona credential show github --reveal

# SSH Agent
$ persona ssh start-agent
$ persona ssh import ~/.ssh/id_ed25519 --name "Production Server"
$ persona ssh list

# 数字钱包
$ persona wallet create --chain eth --name "Main Wallet"
$ persona wallet derive --account 0
$ persona wallet sign --to 0x... --value 0.1

# TOTP 验证
$ persona totp add github --secret JBSWY3DPEHPK3PXP
$ persona totp show github

# 密码生成
$ persona generate --length 24 --symbols
> J#k9!mN@pQ2$rS5^tU8*vW`}</code>
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
};

export default FeaturesPage;
