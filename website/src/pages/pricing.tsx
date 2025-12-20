import React from 'react';
import { Link } from 'umi';
import { Typography, Card, Row, Col, Button, Space, List } from 'antd';
import { CheckOutlined, GithubOutlined, HeartOutlined } from '@ant-design/icons';
import styles from './pricing.less';

const { Title, Paragraph, Text } = Typography;

const PricingPage: React.FC = () => {
  const plans = [
    {
      name: '个人版',
      price: '免费',
      priceNote: '永久免费',
      description: '适合个人用户的完整功能',
      features: [
        '无限密码存储',
        'SSH Agent 集成',
        '数字钱包支持',
        'TOTP 双因素认证',
        '浏览器扩展',
        '跨设备本地同步',
        '密码生成器',
        '安全审计报告',
        'CLI 工具',
      ],
      cta: '立即下载',
      ctaType: 'primary' as const,
      popular: true,
    },
    {
      name: '团队版',
      price: '即将推出',
      priceNote: '',
      description: '为团队协作设计的功能',
      features: [
        '个人版所有功能',
        '团队共享保险库',
        '角色权限管理',
        '审计日志',
        'SCIM 目录同步',
        'SSO 集成',
        '优先技术支持',
        '自定义策略',
      ],
      cta: '加入等待列表',
      ctaType: 'default' as const,
      popular: false,
    },
    {
      name: '企业版',
      price: '联系我们',
      priceNote: '',
      description: '大规模部署和定制需求',
      features: [
        '团队版所有功能',
        '私有化部署',
        'API 集成',
        '合规性报告',
        '专属客户经理',
        'SLA 保障',
        '定制开发',
        '培训服务',
      ],
      cta: '联系销售',
      ctaType: 'default' as const,
      popular: false,
    },
  ];

  const faq = [
    {
      q: 'Persona 真的完全免费吗？',
      a: '是的！个人版是完全免费的，并且会永久保持免费。我们相信每个人都应该能够保护自己的数字身份。',
    },
    {
      q: '为什么选择开源？',
      a: '安全软件应该是透明的。开源让社区可以审计我们的代码，发现并修复潜在问题，这让 Persona 更加安全。',
    },
    {
      q: '如何支持 Persona 的开发？',
      a: '您可以通过 GitHub Sponsors 赞助我们，或者参与开源贡献。每一份支持都会帮助我们做得更好。',
    },
    {
      q: '团队版和企业版什么时候发布？',
      a: '我们正在积极开发中。您可以加入等待列表，我们会在发布时第一时间通知您。',
    },
  ];

  return (
    <div className={styles.page}>
      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroContent}>
          <Title level={1}>简单透明的定价</Title>
          <Paragraph className={styles.heroDesc}>
            个人用户永久免费。企业级功能即将推出。
          </Paragraph>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className={styles.pricing}>
        <div className={styles.sectionContent}>
          <Row gutter={[24, 24]} justify="center">
            {plans.map((plan, index) => (
              <Col xs={24} md={8} key={index}>
                <Card
                  className={`${styles.pricingCard} ${plan.popular ? styles.popular : ''}`}
                >
                  {plan.popular && <div className={styles.popularBadge}>最受欢迎</div>}
                  <div className={styles.planHeader}>
                    <Title level={3}>{plan.name}</Title>
                    <div className={styles.price}>
                      <span className={styles.priceValue}>{plan.price}</span>
                      {plan.priceNote && (
                        <span className={styles.priceNote}>{plan.priceNote}</span>
                      )}
                    </div>
                    <Paragraph className={styles.planDesc}>{plan.description}</Paragraph>
                  </div>
                  <ul className={styles.features}>
                    {plan.features.map((feature, i) => (
                      <li key={i}>
                        <CheckOutlined className={styles.checkIcon} />
                        {feature}
                      </li>
                    ))}
                  </ul>
                  <Button
                    type={plan.ctaType}
                    size="large"
                    block
                    className={styles.ctaButton}
                  >
                    {plan.ctaType === 'primary' ? (
                      <Link to="/download" style={{ color: 'inherit' }}>{plan.cta}</Link>
                    ) : (
                      plan.cta
                    )}
                  </Button>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </section>

      {/* Open Source */}
      <section className={styles.openSource}>
        <div className={styles.sectionContent}>
          <Card className={styles.osCard}>
            <Row gutter={[40, 24]} align="middle">
              <Col xs={24} md={16}>
                <Title level={2}>
                  <GithubOutlined /> 开源万岁
                </Title>
                <Paragraph>
                  Persona 是 100% 开源的。我们相信安全软件应该是透明的，每个人都应该能够审计保护其数据的代码。
                </Paragraph>
                <Paragraph>
                  如果您喜欢 Persona，请考虑在 GitHub 上给我们一个 Star，或者通过 Sponsors 支持我们的开发工作。
                </Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                  <Button
                    type="primary"
                    size="large"
                    icon={<GithubOutlined />}
                    block
                    href="https://github.com/persona-id/persona"
                    target="_blank"
                  >
                    Star on GitHub
                  </Button>
                  <Button
                    size="large"
                    icon={<HeartOutlined />}
                    block
                    href="https://github.com/sponsors/persona-id"
                    target="_blank"
                  >
                    成为赞助者
                  </Button>
                </Space>
              </Col>
            </Row>
          </Card>
        </div>
      </section>

      {/* FAQ */}
      <section className={styles.faq}>
        <div className={styles.sectionContent}>
          <Title level={2} className={styles.faqTitle}>常见问题</Title>
          <Row gutter={[40, 24]}>
            {faq.map((item, index) => (
              <Col xs={24} md={12} key={index}>
                <div className={styles.faqItem}>
                  <Title level={4}>{item.q}</Title>
                  <Paragraph>{item.a}</Paragraph>
                </div>
              </Col>
            ))}
          </Row>
        </div>
      </section>
    </div>
  );
};

export default PricingPage;
