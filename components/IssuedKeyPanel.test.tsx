import React from 'react';
import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import IssuedKeyPanel from './IssuedKeyPanel';

afterEach(cleanup);

describe('IssuedKeyPanel', () => {
  it('lists the grants the server issued', () => {
    render(<IssuedKeyPanel onDone={() => undefined}
      issued={{ id: 'k2', name: 'All', token: 'srp.a.b', expiresAt: '2026-11-20T12:00:00Z', scopes: ['ServerRead', 'ApiKeyManage'] }} />);
    const items = within(screen.getByRole('list', { name: 'Issued permissions' })).getAllByRole('listitem').map(li => li.textContent);
    expect(items).toEqual(['Read servers, rules and traffic', 'Manage API keys']);
  });
});
