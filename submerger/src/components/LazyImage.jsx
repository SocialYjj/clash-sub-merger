import React, { useState, useRef, useEffect } from 'react';

/**
 * Lazy loading image component using Intersection Observer
 */
export default function LazyImage({
  src,
  alt = '',
  className = '',
  placeholder = null,
  onLoad,
  onError,
  ...props
}) {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const [hasError, setHasError] = useState(false);
  const imgRef = useRef(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observer.disconnect();
        }
      },
      {
        rootMargin: '50px',
        threshold: 0.1,
      }
    );

    if (imgRef.current) {
      observer.observe(imgRef.current);
    }

    return () => observer.disconnect();
  }, []);

  const handleLoad = () => {
    setIsLoaded(true);
    onLoad?.();
  };

  const handleError = () => {
    setHasError(true);
    onError?.();
  };

  return (
    <div ref={imgRef} className={`relative ${className}`} {...props}>
      {/* Placeholder while loading */}
      {!isLoaded && !hasError && (
        <div className="absolute inset-0 bg-gray-800 animate-pulse rounded">
          {placeholder}
        </div>
      )}

      {/* Error state */}
      {hasError && (
        <div className="absolute inset-0 bg-gray-800 flex items-center justify-center rounded">
          <span className="text-gray-500 text-sm">加载失败</span>
        </div>
      )}

      {/* Actual image */}
      {isInView && !hasError && (
        <img
          src={src}
          alt={alt}
          className={`transition-opacity duration-300 ${isLoaded ? 'opacity-100' : 'opacity-0'}`}
          onLoad={handleLoad}
          onError={handleError}
        />
      )}
    </div>
  );
}
