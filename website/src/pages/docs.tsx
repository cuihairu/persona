import React from 'react';
import { Link } from 'umi';
import { Typography, Card, Row, Col, Button, Space } from 'antd';
import {
  BookOutlined,
  RocketOutlined,
  ApiOutlined,
  SafetyCertificateOutlined,
  CodeOutlined,
  QuestionCircleOutlined,
  GithubOutlined,
  ReadOutlined,
} from '@ant-design/icons';
import styles from './docs.less';

const { Title, Paragraph } = Typography;

const DocsPage: React.FC = () => {
  const sections = [
    {
      icon: <RocketOutlined />,
      title: '快速开始',
      description: '在几分钟内安装并配置 Persona',
      links: [
        { title: '安装指南', url: '/docs/installation' },
        { title: '基本使用', url: '/docs/basic-usage' },
        { title: '导入数据', url: '/docs/import' },
      ],
    },
    {
      icon: <BookOutlined />,
      title: '用户指南',
      description: '了解 Persona 的所有功能',
      links: [
        { title: '密码管理', url: '/docs/passwords' },
        { title: 'SSH Agent', url: '/docs/ssh-agent' },
        { title: '数字钱包', url: '/docs/wallet' },
        { title: '浏览器扩展', url: '/docs/browser' },
      ],
    },
    {
      icon: <CodeOutlined />,
      title: 'CLI 参考',
      description: '命令行工具完整文档',
      links: [
        { title: '命令概览', url: '/docs/cli/overview' },
        { title: '身份管理', url: '/docs/cli/identity' },
        { title: '凭证操作', url: '/docs/cli/credential' },
        { title: 'SSH 命令', url: '/docs/cli/ssh' },
      ],
    },
    {
      icon: <ApiOutlined />,
      title: 'API 文档',
      description: '开发者集成指南',
      links: [
        { title: 'REST API', url: '/docs/api/rest' },
        { title: 'Native Messaging', url: '/docs/api/native-messaging' },
        { title: 'SSH Agent 协议', url: '/docs/api/ssh-agent' },
      ],
    },
    {
      icon: <SafetyCertificateOutlined />,
      title: '安全设计',
      description: '了解我们的安全架构',
      links: [
        { title: '加密设计', url: '/docs/security/encryption' },
        { title: '密钥管理', url: '/docs/security/keys' },
        { title: '威胁模型', url: '/docs/security/threat-model' },
      ],
    },
    {
      icon: <QuestionCircleOutlined />,
      title: '常见问题',
      description: '解答您的疑问',
      links: [
        { title: 'FAQ', url: '/docs/faq' },
        { title: '故障排除', url: '/docs/troubleshooting' },
        { title: '数据迁移', url: '/docs/migration' },
      ],
    },
  ];

  return (
    <div className={styles.page}>
      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroContent}>
          <Title level={1}>文档中心</Title>
          <Paragraph className={styles.heroDesc}>
            学习如何使用 Persona 保护您的数字身份
          </Paragraph>
        </div>
      </section>

      {/* Quick Links */}
      <section className={styles.quickLinks}>
        <div className={styles.sectionContent}>
          <Row gutter={[24, 24]}>
            <Col xs={24} md={8}>
              <Card className={styles.quickCard} hoverable>
                <RocketOutlined className={styles.quickIcon} />
                <Title level={4}>5 分钟快速上手</Title>
                <Paragraph>从安装到配置，快速入门 Persona</Paragraph>
                <Button type="primary">开始学习</Button>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card className={styles.quickCard} hoverable>
                <ReadOutlined className={styles.quickIcon} />
                <Title level={4}>完整文档</Title>
                <Paragraph>查看托管在 GitHub Pages 的详细文档</Paragraph>
                <Button href="https://persona-id.github.io/persona/" target="_blank">
                  访问文档站
                </Button>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card className={styles.quickCard} hoverable>
                <GithubOutlined className={styles.quickIcon} />
                <Title level={4}>GitHub Wiki</Title>
                <Paragraph>社区维护的知识库和最佳实践</Paragraph>
                <Button href="https://github.com/persona-id/persona/wiki" target="_blank">
                  查看 Wiki
                </Button>
              </Card>
            </Col>
          </Row>
        </div>
      </section>

      {/* Documentation Sections */}
      <section className={styles.sections}>
        <div className={styles.sectionContent}>
          <Row gutter={[32, 32]}>
            {sections.map((section, index) => (
              <Col xs={24} md={12} lg={8} key={index}>
                <Card className={styles.sectionCard}>
                  <div className={styles.sectionIcon}>{section.icon}</div>
                  <Title level={4}>{section.title}</Title>
                  <Paragraph className={styles.sectionDesc}>{section.description}</Paragraph>
                  <ul className={styles.sectionLinks}>
                    {section.links.map((link, i) => (
                      <li key={i}>
                        <a href={link.url}>{link.title}</a>
                      </li>
                    ))}
                  </ul>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* Community */}
      <section className={styles.community}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.communityTitle}>需要帮助？</Title>
          <Paragraph className={styles.communityDesc}>
            加入我们的社区，获取支持和最新资讯
          </Paragraph>
          <Space size="large">
            <Button size="large" icon={<GithubOutlined />} href="https://github.com/persona-id/persona/discussions" target="_blank">
              GitHub Discussions
            </Button>
            <Button size="large" href="https://github.com/persona-id/persona/issues" target="_blank">
              报告问题
            </Button>
          </Space>
        </div>
      </section>
    </div>
  );
};

export default DocsPage;
