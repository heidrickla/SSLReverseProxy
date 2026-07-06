import { useEffect, useRef } from 'react';

/**
 * A custom React hook that enables horizontal scrolling with the mouse wheel
 * on an element when only a horizontal scrollbar is present (and no vertical scrollbar).
 */
export const useHorizontalScroll = () => {
  const elRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = elRef.current;
    if (element) {
      const onWheel = (e: WheelEvent) => {
        const hasHorizontalScrollbar = element.scrollWidth > element.clientWidth;
        const hasVerticalScrollbar = element.scrollHeight > element.clientHeight;
        
        // Only intervene if there's a horizontal scrollbar, no vertical scrollbar,
        // and the wheel event is primarily vertical.
        // This avoids interfering with native horizontal scroll on trackpads.
        if (!hasHorizontalScrollbar || hasVerticalScrollbar || e.deltaX !== 0) {
          return;
        }

        e.preventDefault();
        element.scrollLeft += e.deltaY;
      };

      // Add event listener. passive: false is necessary to allow preventDefault().
      element.addEventListener('wheel', onWheel, { passive: false });

      return () => {
        element.removeEventListener('wheel', onWheel);
      };
    }
  }, []);

  return elRef;
};
