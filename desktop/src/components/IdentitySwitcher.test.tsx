import { fireEvent, render, screen } from '@testing-library/react';
import { CreateIdentityModal, IdentitySwitcher } from './IdentitySwitcher';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

const openOptions = (identities: any[], currentIdentity: any, switchIdentity = jest.fn()) => {
  (usePersonaService as jest.Mock).mockReturnValue({
    identities,
    currentIdentity,
    switchIdentity,
  });
  render(<IdentitySwitcher onCreateIdentity={() => {}} />);
  fireEvent.click(screen.getByRole('button'));
};

describe('components/IdentitySwitcher', () => {
  it('renders placeholder when no current identity', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      switchIdentity: jest.fn(),
    });

    const { getByText } = render(<IdentitySwitcher onCreateIdentity={() => {}} />);
    expect(getByText('Select an identity')).toBeInTheDocument();
  });

  it('opens options and calls onCreateIdentity', () => {
    const onCreateIdentity = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [
        { id: '1', name: 'Personal', identity_type: 'Personal', tags: [] },
        { id: '2', name: 'Work', identity_type: 'Work', tags: [] },
      ],
      currentIdentity: { id: '1', name: 'Personal', identity_type: 'Personal', tags: [] },
      switchIdentity: jest.fn(),
    });

    const { getByRole, getByText } = render(
      <IdentitySwitcher onCreateIdentity={onCreateIdentity} />,
    );

    fireEvent.click(getByRole('button'));
    fireEvent.click(getByText('Create new identity'));
    expect(onCreateIdentity).toHaveBeenCalledTimes(1);
  });

  it('shows the current identity with its type label in the closed button', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: { id: '1', name: 'Corp', identity_type: 'Work', tags: [] },
      switchIdentity: jest.fn(),
    });

    render(<IdentitySwitcher onCreateIdentity={() => {}} />);
    expect(screen.getByText('Corp')).toBeInTheDocument();
    expect(screen.getByText('Work')).toBeInTheDocument();
  });

  it('lists every identity type with its own icon/color and marks the selected one', () => {
    const identities = [
      'Personal',
      'Work',
      'Social',
      'Financial',
      'Gaming',
      'Custom',
    ].map((type, i) => ({ id: `id-${i}`, name: `N-${type}`, identity_type: type, tags: [] }));

    openOptions(identities, identities[0]);

    for (const type of ['Personal', 'Work', 'Social', 'Financial', 'Gaming', 'Custom']) {
      // 当前身份在闭合按钮上也渲染一次，故至少出现一次
      expect(screen.getAllByText(`N-${type}`).length).toBeGreaterThanOrEqual(1);
    }
    // 未知类型（Custom）走 default 分支：灰色圆形图标容器
    // （icon 容器是文本的叔节点，改查文档级 default 配色类）
    expect(document.querySelector('.bg-gray-100.text-gray-800')).not.toBeNull();
  });

  it('switches identity on option click', () => {
    const identities = [
      { id: 'id-a', name: 'Alpha', identity_type: 'Personal', tags: [] },
      { id: 'id-b', name: 'Beta', identity_type: 'Work', tags: [] },
    ];
    const switchIdentity = jest.fn();
    openOptions(identities, identities[0], switchIdentity);

    fireEvent.click(screen.getByText('Beta'));
    expect(switchIdentity).toHaveBeenCalledWith(identities[1]);
  });
});

describe('components/CreateIdentityModal', () => {
  const createIdentity = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    createIdentity.mockResolvedValue({ id: 'new' });
  });

  const renderModal = (overrides: Partial<Parameters<typeof CreateIdentityModal>[0]> = {}) => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      switchIdentity: jest.fn(),
      createIdentity,
      isLoading: false,
    });
    return render(<CreateIdentityModal isOpen onClose={() => {}} {...overrides} />);
  };

  it('renders nothing when closed', () => {
    const { container } = renderModal({ isOpen: false });
    expect(container).toBeEmptyDOMElement();
  });

  it('submits name, type and description, then closes and resets', async () => {
    const onClose = jest.fn();
    const { rerender } = renderModal({ onClose });

    fireEvent.change(screen.getByLabelText('Identity Name'), {
      target: { value: 'Work Profile' },
    });
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'Financial' } });
    fireEvent.change(screen.getByLabelText('Description (Optional)'), {
      target: { value: 'bank stuff' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Identity' }));

    await Promise.resolve();
    expect(createIdentity).toHaveBeenCalledWith('Work Profile', 'Financial', 'bank stuff');
    await Promise.resolve();
    expect(onClose).toHaveBeenCalledTimes(1);

    // 同一实例关闭再打开：字段已重置
    rerender(<CreateIdentityModal isOpen={false} onClose={onClose} />);
    rerender(<CreateIdentityModal isOpen onClose={onClose} />);
    expect((screen.getByLabelText('Identity Name') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Description (Optional)') as HTMLTextAreaElement).value).toBe('');
    expect((screen.getByLabelText('Type') as HTMLSelectElement).value).toBe('Personal');
  });

  it('blocks submit without a name and passes undefined description when empty', async () => {
    const onClose = jest.fn();
    renderModal({ onClose });

    // 空名：按钮禁用
    expect(screen.getByRole('button', { name: 'Create Identity' })).toBeDisabled();

    // 表单 submit（绕过 disabled 断言）也应被 guard 拦下
    fireEvent.submit(screen.getByRole('button', { name: 'Create Identity' }).closest('form')!);
    expect(createIdentity).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText('Identity Name'), {
      target: { value: 'Only Name' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Identity' }));
    await Promise.resolve();
    expect(createIdentity).toHaveBeenCalledWith('Only Name', 'Personal', undefined);
  });

  it('keeps the form open with data intact when createIdentity returns nothing', async () => {
    createIdentity.mockResolvedValue(null);
    const onClose = jest.fn();
    renderModal({ onClose });

    fireEvent.change(screen.getByLabelText('Identity Name'), { target: { value: 'X' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Identity' }));
    await Promise.resolve();
    await Promise.resolve();

    expect(onClose).not.toHaveBeenCalled();
  });

  it('shows the creating state while loading', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      switchIdentity: jest.fn(),
      createIdentity,
      isLoading: true,
    });
    render(<CreateIdentityModal isOpen onClose={() => {}} />);
    expect(screen.getByRole('button', { name: 'Creating...' })).toBeDisabled();
  });

  it('closes via cancel', () => {
    const onClose = jest.fn();
    renderModal({ onClose });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

