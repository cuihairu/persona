/**
 * End-to-end tests for the Persona desktop application
 *
 * These tests verify the integration between the React frontend
 * and the Tauri backend commands.
 */

import { invoke } from '@tauri-apps/api/tauri';
import type { ApiResponse, Identity, Credential } from '@/types';
import { personaAPI } from '@/utils/api';

// Mock Tauri invoke for testing
const mockInvoke = jest.fn();
jest.mock('@tauri-apps/api/tauri', () => ({
  invoke: (...args: any[]) => mockInvoke(...args),
}));

const invokeApi = <T>(command: string, args?: Record<string, unknown>) =>
  args ? invoke<ApiResponse<T>>(command, args) : invoke<ApiResponse<T>>(command);

describe('Desktop Application Integration Tests', () => {
  beforeEach(() => {
    mockInvoke.mockClear();
  });

  describe('Service Initialization', () => {
    it('should initialize service with master password', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<boolean>('init_service', {
        request: {
          master_password: 'test_password_123',
          db_path: undefined,
        },
      });

      expect(mockInvoke).toHaveBeenCalledWith('init_service', {
        request: {
          master_password: 'test_password_123',
          db_path: undefined,
        },
      });

      expect(result).toEqual(mockResponse);
    });

    it('should handle initialization errors', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: false,
        data: undefined,
        error: 'Invalid master password',
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<boolean>('init_service', {
        request: {
          master_password: 'wrong_password',
          db_path: undefined,
        },
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid master password');
    });
  });

  describe('Identity Management', () => {
    const mockIdentity: Identity = {
      id: '123e4567-e89b-12d3-a456-426614174000',
      name: 'Test Identity',
      identity_type: 'Personal',
      description: 'A test identity',
      email: 'test@example.com',
      phone: undefined,
      ssh_key: undefined,
      gpg_key: undefined,
      tags: [],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
    };

    it('should create a new identity', async () => {
      const mockResponse: ApiResponse<Identity> = {
        success: true,
        data: mockIdentity,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Identity>('create_identity', {
        request: {
          name: 'Test Identity',
          identity_type: 'Personal',
          description: 'A test identity',
          email: 'test@example.com',
        },
      });

      expect(mockInvoke).toHaveBeenCalledWith('create_identity', {
        request: {
          name: 'Test Identity',
          identity_type: 'Personal',
          description: 'A test identity',
          email: 'test@example.com',
        },
      });

      expect(result.data).toEqual(mockIdentity);
    });

    it('should retrieve all identities', async () => {
      const mockResponse: ApiResponse<Identity[]> = {
        success: true,
        data: [mockIdentity],
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Identity[]>('get_identities');

      expect(mockInvoke).toHaveBeenCalledWith('get_identities');
      expect(result.data).toHaveLength(1);
      expect(result.data![0]).toEqual(mockIdentity);
    });

    it('should update an identity', async () => {
      const mockIdentity: Identity = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'Updated Identity',
        identity_type: 'Work',
        description: 'Updated description',
        email: 'updated@example.com',
        phone: '123456789',
        ssh_key: undefined,
        gpg_key: undefined,
        tags: ['work'],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        is_active: true,
      };

      const mockResponse: ApiResponse<Identity> = {
        success: true,
        data: mockIdentity,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await personaAPI.updateIdentity({
        id: mockIdentity.id,
        name: mockIdentity.name,
        identity_type: mockIdentity.identity_type,
        description: mockIdentity.description,
        email: mockIdentity.email,
        phone: mockIdentity.phone,
        tags: mockIdentity.tags,
      });

      expect(mockInvoke).toHaveBeenCalledWith('update_identity', {
        request: {
          id: mockIdentity.id,
          name: mockIdentity.name,
          identity_type: mockIdentity.identity_type,
          description: mockIdentity.description,
          email: mockIdentity.email,
          phone: mockIdentity.phone,
          tags: mockIdentity.tags,
        },
      });
      expect(result).toEqual(mockResponse);
    });

    it('should delete an identity', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await personaAPI.deleteIdentity('123e4567-e89b-12d3-a456-426614174000');

      expect(mockInvoke).toHaveBeenCalledWith('delete_identity', {
        identity_id: '123e4567-e89b-12d3-a456-426614174000',
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('Credential Management', () => {
    const mockCredential: Credential = {
      id: '987fcdeb-51d2-43c1-b456-426614174000',
      identity_id: '123e4567-e89b-12d3-a456-426614174000',
      name: 'Test Website',
      credential_type: 'Password',
      security_level: 'High',
      url: 'https://example.com',
      username: 'testuser',
      notes: undefined,
      tags: [],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      last_accessed: undefined,
      is_active: true,
      is_favorite: false,
    };

    it('should create a password credential', async () => {
      const mockResponse: ApiResponse<Credential> = {
        success: true,
        data: mockCredential,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Credential>('create_credential', {
        request: {
          identity_id: '123e4567-e89b-12d3-a456-426614174000',
          name: 'Test Website',
          credential_type: 'Password',
          security_level: 'High',
          url: 'https://example.com',
          username: 'testuser',
          credential_data: {
            type: 'Password',
            password: 'secret123',
            email: 'test@example.com',
            security_questions: [],
          },
        },
      });

      expect(result.data).toEqual(mockCredential);
    });

    it('should retrieve credentials for an identity', async () => {
      const mockResponse: ApiResponse<Credential[]> = {
        success: true,
        data: [mockCredential],
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Credential[]>('get_credentials_for_identity', {
        identity_id: '123e4567-e89b-12d3-a456-426614174000',
      });

      expect(result.data).toHaveLength(1);
      expect(result.data![0]).toEqual(mockCredential);
    });

    it('should search credentials', async () => {
      const mockResponse: ApiResponse<Credential[]> = {
        success: true,
        data: [mockCredential],
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Credential[]>('search_credentials', {
        query: 'Test',
      });

      expect(mockInvoke).toHaveBeenCalledWith('search_credentials', {
        query: 'Test',
      });
      expect(result.data).toHaveLength(1);
    });

    it('should toggle credential favorite status', async () => {
      const favoriteCredential = { ...mockCredential, is_favorite: true };
      const mockResponse: ApiResponse<Credential> = {
        success: true,
        data: favoriteCredential,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<Credential>('toggle_credential_favorite', {
        credential_id: mockCredential.id,
      });

      expect(result.data!.is_favorite).toBe(true);
    });

    it('should delete a credential', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<boolean>('delete_credential', {
        credential_id: mockCredential.id,
      });

      expect(result.data).toBe(true);
    });

    it('should request a TOTP code for a credential', async () => {
      const mockResponse: ApiResponse<any> = {
        success: true,
        data: {
          code: '123456',
          remaining_seconds: 12,
          period: 30,
          digits: 6,
          algorithm: 'SHA1',
          issuer: 'GitHub',
          account_name: 'user@example.com',
        },
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await personaAPI.getTotpCode('123e4567-e89b-12d3-a456-426614174000');

      expect(mockInvoke).toHaveBeenCalledWith('get_totp_code', {
        credential_id: '123e4567-e89b-12d3-a456-426614174000',
      });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('Utility Functions', () => {
    it('should generate a password', async () => {
      const mockResponse: ApiResponse<string> = {
        success: true,
        data: 'GeneratedPassword123!',
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<string>('generate_password', {
        length: 16,
        include_symbols: true,
      });

      expect(mockInvoke).toHaveBeenCalledWith('generate_password', {
        length: 16,
        include_symbols: true,
      });

      expect(result.data).toBe('GeneratedPassword123!');
    });

    it('should retrieve service statistics', async () => {
      const mockStats = {
        total_identities: 1,
        total_credentials: 2,
        active_credentials: 2,
        favorite_credentials: 1,
        credential_types: { Password: 1, ApiKey: 1 },
        security_levels: { High: 1, Medium: 1 },
      };

      const mockResponse: ApiResponse<typeof mockStats> = {
        success: true,
        data: mockStats,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<typeof mockStats>('get_statistics');

      expect(result.data).toEqual(mockStats);
    });
  });

  describe('Service State Management', () => {
    it('should check if service is unlocked', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<boolean>('is_service_unlocked');

      expect(result.data).toBe(true);
    });

    it('should lock the service', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invokeApi<boolean>('lock_service');

      expect(result.data).toBe(true);
    });
  });

  describe('Wallet Management', () => {
    it('should list wallets for an identity', async () => {
      const mockResponse: ApiResponse<{ wallets: any[] }> = {
        success: true,
        data: { wallets: [] },
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      await personaAPI.walletList('123e4567-e89b-12d3-a456-426614174000');

      expect(mockInvoke).toHaveBeenCalledWith('wallet_list', {
        identity_id: '123e4567-e89b-12d3-a456-426614174000',
      });
    });

    it('should generate a wallet for an identity', async () => {
      const mockResponse: ApiResponse<any> = {
        success: true,
        data: {
          wallet_id: '11111111-1111-1111-1111-111111111111',
          name: 'My Wallet',
          network: 'Ethereum',
          mnemonic: 'word1 word2 word3',
          first_address: '0xabc',
        },
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      await personaAPI.walletGenerate('123e4567-e89b-12d3-a456-426614174000', {
        name: 'My Wallet',
        network: 'Ethereum',
        wallet_type: 'hd',
        password: 'password123',
        address_count: 5,
      });

      expect(mockInvoke).toHaveBeenCalledWith('wallet_generate', {
        identity_id: '123e4567-e89b-12d3-a456-426614174000',
        request: {
          name: 'My Wallet',
          network: 'Ethereum',
          wallet_type: 'hd',
          password: 'password123',
          address_count: 5,
        },
      });
    });

    it('should import a wallet for an identity', async () => {
      const mockResponse: ApiResponse<any> = {
        success: true,
        data: {
          id: '11111111-1111-1111-1111-111111111111',
          name: 'Imported Wallet',
          network: 'Ethereum',
          wallet_type: 'SingleAddress',
          balance: '-',
          address_count: 1,
          watch_only: false,
          security_level: 'Medium',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      await personaAPI.walletImport('123e4567-e89b-12d3-a456-426614174000', {
        name: 'Imported Wallet',
        network: 'Ethereum',
        import_type: 'private_key',
        data: '0xdeadbeef',
        password: 'password123',
      });

      expect(mockInvoke).toHaveBeenCalledWith('wallet_import', {
        identity_id: '123e4567-e89b-12d3-a456-426614174000',
        request: {
          name: 'Imported Wallet',
          network: 'Ethereum',
          import_type: 'private_key',
          data: '0xdeadbeef',
          password: 'password123',
        },
      });
    });

    it('should add an address for a wallet', async () => {
      const mockResponse: ApiResponse<any> = {
        success: true,
        data: {
          address: '0xabc',
          address_type: 'ETH',
          index: 0,
          used: false,
          balance: '-',
          derivation_path: null,
        },
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      await personaAPI.walletAddAddress('11111111-1111-1111-1111-111111111111', 'password123');

      expect(mockInvoke).toHaveBeenCalledWith('wallet_add_address', {
        wallet_id: '11111111-1111-1111-1111-111111111111',
        password: 'password123',
      });
    });
  });
});

// Integration test with React components would go here
// These would test the actual UI interactions with mocked backend responses
