/**
 * Reusable skeleton-screen primitives.
 *
 * Modeled on the DashboardSkeleton pattern in Dashboard.jsx: a top-level
 * container carries `animate-pulse` while the blocks inside are plain
 * surface-colored shapes, so everything pulses together. All colors use the
 * semantic theme tokens, so skeletons render correctly in both themes.
 *
 * Usage:
 *   if (initialLoading) {
 *     return (
 *       <div className="space-y-6 animate-pulse p-1">
 *         <SkeletonHeader />
 *         <SkeletonCardGrid count={8} />
 *       </div>
 *     );
 *   }
 */

export function Skeleton({ className = '' }) {
  return <div aria-hidden="true" className={`bg-surface-3/50 rounded ${className}`} />;
}

/**
 * Standard page header placeholder: title + subtitle on the left, optional
 * action button block on the right.
 */
export function SkeletonHeader({
  titleWidth = 'w-32',
  subWidth = 'w-48',
  showAction = true,
  actionClassName = '',
}) {
  return (
    <div className="flex items-center justify-between mb-8">
      <div className="space-y-2">
        <div className={`h-8 ${titleWidth} bg-surface-2 rounded-lg`} />
        <div className={`h-4 ${subWidth} bg-surface-2/60 rounded`} />
      </div>
      {showAction && (
        <div className={`h-8 w-36 bg-surface-2/50 rounded-lg ${actionClassName}`} />
      )}
    </div>
  );
}

/**
 * Grid of card placeholders (stat cards, subscription/user/template cards).
 * Pass `gridClassName` to match the page's real grid breakpoints.
 */
export function SkeletonCardGrid({
  count = 8,
  gridClassName = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4',
  cardClassName = 'h-44',
}) {
  return (
    <div className={gridClassName} aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className={`rounded-2xl border border-line-soft bg-surface-2/30 p-5 space-y-4 ${cardClassName}`}
        >
          <div className="flex items-center justify-between">
            <div className="w-10 h-10 rounded-xl bg-surface-3/40" />
            <div className="w-16 h-5 rounded-full bg-surface-3/30" />
          </div>
          <div className="space-y-2">
            <div className="h-4 w-3/4 bg-surface-3/40 rounded" />
            <div className="h-3 w-1/2 bg-surface-3/30 rounded" />
            <div className="h-3 w-2/3 bg-surface-3/30 rounded" />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Stat-card grid placeholder matching the Dashboard's top row.
 */
export function SkeletonStatGrid({
  count = 4,
  className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4',
}) {
  return (
    <div className={className} aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className="h-36 rounded-2xl border border-line-soft bg-surface-2/30 p-6 space-y-4"
        >
          <div className="flex justify-between items-center">
            <div className="w-12 h-12 rounded-xl bg-surface-3/40" />
            <div className="w-16 h-5 rounded-full bg-surface-3/30" />
          </div>
          <div className="space-y-2">
            <div className="h-3 w-16 bg-surface-3/30 rounded" />
            <div className="h-7 w-24 bg-surface-3/50 rounded" />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Panel/chart-card placeholder shell with a title bar; children fill the body.
 */
export function SkeletonPanel({ className = 'h-80', children }) {
  return (
    <div
      className={`${className} rounded-2xl border border-line-soft bg-surface-2/30 p-6 space-y-4`}
      aria-hidden="true"
    >
      <div className="h-6 w-32 bg-surface-3/40 rounded" />
      {children}
    </div>
  );
}

/**
 * Labeled bar-row placeholder used by the Dashboard chart panels.
 * Each row: two small bars on one line, a full-width progress bar below.
 */
export function SkeletonRows({ rows = 5, className = 'space-y-3 pt-2' }) {
  return (
    <div className={className} aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="space-y-2">
          <div className="flex justify-between">
            <div className="h-4 w-20 bg-surface-3/30 rounded" />
            <div className="h-4 w-10 bg-surface-3/30 rounded" />
          </div>
          <div className="h-2 w-full bg-surface-3/20 rounded-full" />
        </div>
      ))}
    </div>
  );
}

/**
 * Table-shaped placeholder (header strip + rows of bars) for pages whose
 * content is a table, e.g. the nodes list.
 */
export function SkeletonTableRows({ rows = 10, className = 'space-y-2.5 p-4' }) {
  return (
    <div className={className} aria-hidden="true">
      <div className="flex items-center gap-3 pb-2 border-b border-line">
        <div className="h-3.5 w-4 bg-surface-3/40 rounded" />
        <div className="h-3.5 w-40 bg-surface-3/40 rounded" />
        <div className="h-3.5 w-16 bg-surface-3/30 rounded" />
        <div className="h-3.5 w-12 bg-surface-3/30 rounded" />
        <div className="h-3.5 w-16 bg-surface-3/30 rounded" />
        <div className="h-3.5 w-14 bg-surface-3/30 rounded" />
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="h-4 w-4 bg-surface-3/30 rounded" />
          <div className={`h-4 bg-surface-3/40 rounded ${i % 3 === 1 ? 'w-1/3' : 'w-1/4'}`} />
          <div className="h-4 w-16 bg-surface-3/30 rounded" />
          <div className="h-4 w-12 bg-surface-3/30 rounded" />
          <div className="h-4 w-16 bg-surface-3/30 rounded" />
          <div className="h-4 w-14 bg-surface-3/30 rounded" />
        </div>
      ))}
    </div>
  );
}
