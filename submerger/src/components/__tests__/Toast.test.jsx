import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import Toast from '../Toast.jsx';

describe('Toast', () => {
  it('renders nothing when hidden', () => {
    expect(renderToStaticMarkup(<Toast show={false} message="保存成功" />)).toBe('');
  });

  it('renders message with style for error notifications', () => {
    const markup = renderToStaticMarkup(<Toast show message="保存失败" type="error" />);

    expect(markup).toContain('保存失败');
    expect(markup).toContain('border-red-500/20');
    expect(markup).toContain('text-red-400');
  });
});
