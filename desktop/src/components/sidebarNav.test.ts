import type { TFunction } from 'i18next';
import { filterLabel, viewForFilter } from './sidebarNav';

const passthrough = ((key: string) => key) as TFunction;

describe('components/sidebarNav', () => {
  it('viewForFilter maps the generator tool to the generator view', () => {
    expect(viewForFilter({ kind: 'generator' })).toBe('generator');
  });

  it('filterLabel falls back to all items for an unknown identity id', () => {
    const label = filterLabel(
      passthrough,
      { kind: 'identity', value: 'missing-id' },
      [{ id: 'real-id', name: 'Real' } as any],
    );
    expect(label).toBe('sidebar.allItems');
  });

  it('filterLabel resolves a known identity id to its name', () => {
    const label = filterLabel(
      passthrough,
      { kind: 'identity', value: 'real-id' },
      [{ id: 'real-id', name: 'Real' } as any],
    );
    expect(label).toBe('Real');
  });
});
