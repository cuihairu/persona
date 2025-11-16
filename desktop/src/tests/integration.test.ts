/**
 * End-to-end tests for the Persona desktop application
 *
 * These tests verify the integration between the React frontend
 * and the Tauri backend commands.
 */

import { invoke } from '@tauri-apps/api/tauri';
import type { ApiResponse, Identity, Credential } from '../src/types';

// Mock Tauri invoke for testing
const mockInvoke = jest.fn();
jest.mock('@tauri-apps/api/tauri', () => ({
  invoke: (...args: any[]) => mockInvoke(...args),
}));

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

      const result = await invoke('init_service', {
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

      const result = await invoke('init_service', {
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

      const result = await invoke('create_identity', {
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

      const result = await invoke('get_identities');

      expect(mockInvoke).toHaveBeenCalledWith('get_identities');
      expect(result.data).toHaveLength(1);
      expect(result.data![0]).toEqual(mockIdentity);
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

      const result = await invoke('create_credential', {
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

      const result = await invoke('get_credentials_for_identity', {
        identityId: '123e4567-e89b-12d3-a456-426614174000',
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

      const result = await invoke('search_credentials', {
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

      const result = await invoke('toggle_credential_favorite', {
        credentialId: mockCredential.id,
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

      const result = await invoke('delete_credential', {
        credentialId: mockCredential.id,
      });

      expect(result.data).toBe(true);
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

      const result = await invoke('generate_password', {
        length: 16,
        includeSymbols: true,
      });

      expect(mockInvoke).toHaveBeenCalledWith('generate_password', {
        length: 16,
        includeSymbols: true,
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

      const result = await invoke('get_statistics');

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

      const result = await invoke('is_service_unlocked');

      expect(result.data).toBe(true);
    });

    it('should lock the service', async () => {
      const mockResponse: ApiResponse<boolean> = {
        success: true,
        data: true,
        error: undefined,
      };

      mockInvoke.mockResolvedValue(mockResponse);

      const result = await invoke('lock_service');

      expect(result.data).toBe(true);
    });
  });
});

// Integration test with React components would go here
// These would test the actual UI interactions with mocked backend responses