import { fireEvent, render, screen } from '@testing-library/react';
import DataScopeConsentModal from './DataScopeConsentModal';

describe('components/DataScopeConsentModal', () => {
  const onConfirm = jest.fn();
  const onCancel = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the audit disclosure with server-visible and never-leaves lists', () => {
    render(<DataScopeConsentModal scope="audit" onConfirm={onConfirm} onCancel={onCancel} />);

    expect(screen.getByTestId('data-scope-modal')).toHaveAttribute('data-scope', 'audit');
    expect(
      screen.getByRole('heading', { name: '开启前明示：服务器会看到什么' }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('data-scope-sees')).toHaveTextContent('连接来源 IP');
    expect(screen.getByTestId('data-scope-not-sees')).toHaveTextContent('主密码、设备私钥');
    // 通道边界注：审计开关与 E2EE 加入是两处显式动作
    expect(screen.getByText(/此开关只控制审计事件上报/)).toBeInTheDocument();
  });

  it('renders the e2ee disclosure with the envelope relay scope', () => {
    render(<DataScopeConsentModal scope="e2ee" onConfirm={onConfirm} onCancel={onCancel} />);

    expect(screen.getByTestId('data-scope-modal')).toHaveAttribute('data-scope', 'e2ee');
    expect(
      screen.getByRole('heading', { name: '加入前明示：服务器能看到什么' }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('data-scope-sees')).toHaveTextContent('密文操作日志');
    expect(screen.getByTestId('data-scope-sees')).toHaveTextContent('尺寸侧信道');
    expect(screen.getByTestId('data-scope-not-sees')).toHaveTextContent('Passkey');
    // 通道边界注只在 audit 面
    expect(screen.queryByText(/此开关只控制审计事件上报/)).not.toBeInTheDocument();
  });

  it('放行只走确认按钮', () => {
    render(<DataScopeConsentModal scope="audit" onConfirm={onConfirm} onCancel={onCancel} />);

    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('取消按钮 / 关闭图标 / Esc / 点空白一律不放行', () => {
    render(<DataScopeConsentModal scope="audit" onConfirm={onConfirm} onCancel={onCancel} />);

    fireEvent.click(screen.getByTestId('data-scope-cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    expect(onCancel).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(3);

    fireEvent.mouseDown(screen.getByTestId('data-scope-modal'));
    expect(onCancel).toHaveBeenCalledTimes(4);

    expect(onConfirm).not.toHaveBeenCalled();
  });
});
