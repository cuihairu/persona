import { render } from '@testing-library/react';
import Highlight from './Highlight';

describe('components/Highlight', () => {
  it('renders the whole text unchanged for an empty query', () => {
    const { container, queryByTestId } = render(<Highlight text="hello world" query="  " />);
    expect(container.textContent).toBe('hello world');
    expect(queryByTestId('highlight-hit')).toBeNull();
  });

  it('wraps every case-insensitive match in a mark', () => {
    const { getAllByTestId, container } = render(<Highlight text="Hello Hello" query="hello" />);
    expect(getAllByTestId('highlight-hit')).toHaveLength(2);
    expect(container.textContent).toBe('Hello Hello');
  });

  it('renders plain text when there is no match', () => {
    const { queryByTestId, container } = render(<Highlight text="abc" query="zzz" />);
    expect(queryByTestId('highlight-hit')).toBeNull();
    expect(container.textContent).toBe('abc');
  });
});
