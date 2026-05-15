import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import ConfirmModal from '../ConfirmModal.jsx';

describe('ConfirmModal', () => {
  it('renders nothing while closed', () => {
    const markup = renderToStaticMarkup(
      <ConfirmModal isOpen={false} onClose={vi.fn()} onConfirm={vi.fn()} />
    );

    expect(markup).toBe('');
  });

  it('renders custom title, message and action labels when open', () => {
    const markup = renderToStaticMarkup(
      <ConfirmModal
        isOpen
        onClose={vi.fn()}
        onConfirm={vi.fn()}
        title="删除节点"
        message="确认删除这个节点吗？"
        confirmText="删除"
        cancelText="先不删"
        type="danger"
      />
    );

    expect(markup).toContain('删除节点');
    expect(markup).toContain('确认删除这个节点吗？');
    expect(markup).toContain('删除');
    expect(markup).toContain('先不删');
    expect(markup).toContain('bg-red-600');
  });
});
