// CreateCredentialModal 测试共享件：模块级 mock、默认钉值、fixture 与定位工具
// 各测试文件自带 jest.mock 工厂指向这里的实例（单实例保证 beforeEach 重钉全局生效）
import { fireEvent, screen } from '@testing-library/react';
import type { Identity } from '@/types';

export const mockUsePersonaService = jest.fn();
export const createCredential = jest.fn();
export const generatePassword = jest.fn();
export const updateCredential = jest.fn();
export const updateCredentialData = jest.fn();

// 钱包表单直连 personaAPI 的纯计算命令（生成/校验助记词，不触库）
export const walletValidateMnemonic = jest.fn().mockResolvedValue({
  success: true,
  data: { valid: true, word_count: 2, error: null },
});
export const walletGenerateMnemonic = jest.fn().mockResolvedValue({
  success: true,
  data: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
});

// 自定义字段整表读写（编辑表单增删改 UI）；默认成功空表，各用例覆写
export const getCredentialCustomFields = jest
  .fn()
  .mockResolvedValue({ success: true, data: [] });
export const setCredentialCustomFields = jest
  .fn()
  .mockResolvedValue({ success: true, data: [] });


// modal 接 useReauth 处理 payload 保存的 REAUTH_REQUIRED；
// 默认"取消"语义（resolve false → 不自动重试），REAUTH 用例断言编排
export const mockReauth = {
  isOpen: false,
  error: null as string | null,
  isVerifying: false,
  requestReauth: jest.fn().mockResolvedValue(false),
  submit: jest.fn(),
  cancel: jest.fn(),
};

/** 每个用例前复位并重钉默认值（clearAllMocks 不清 mockResolvedValue，防用例间串味）。 */
export const pinDefaultMocks = (): void => {
  jest.clearAllMocks();
  createCredential.mockResolvedValue({ id: 'c-1' });
  generatePassword.mockResolvedValue('');
  updateCredential.mockResolvedValue({ id: 'c-9' });
  updateCredentialData.mockResolvedValue({ success: true, data: { id: 'c-9' } });
  // 重钉默认（clearAllMocks 不清 mockResolvedValue，防用例间串味）
  getCredentialCustomFields.mockResolvedValue({ success: true, data: [] });
  setCredentialCustomFields.mockResolvedValue({ success: true, data: [] });
  mockUsePersonaService.mockReturnValue({
    currentIdentity: identity,
    createCredential,
    generatePassword,
    isLoading: false,
  });
};

export const identity = {
  id: 'id-1',
  name: 'Personal',
  identity_type: 'Personal',
  description: null,
  email: null,
  phone: null,
  ssh_key: null,
  gpg_key: null,
  tags: [],
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  is_active: true,
} as unknown as Identity;

/** 组件 label 未绑定 htmlFor，select 一律按值定位（Type 恒为表单里第一个 combobox）。 */
export const getSelect = (value: string): HTMLSelectElement =>
  screen
    .getAllByRole('combobox')

    .find((el) => (el as HTMLSelectElement).value === value) as HTMLSelectElement;

export const selectType = (type: string) => {
  fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: type } });
};
