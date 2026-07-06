// Safe reading of user-supplied image files for avatars/logos.
//
// Two risks are addressed:
//  1. SVG images can carry <script>/onload payloads. Even though we render into
//     <img> (which does not execute script), we reject SVG outright and only
//     accept raster formats to avoid ever persisting active content.
//  2. Unbounded data URLs bloat localStorage. We cap the input size.
// The file is re-encoded through a canvas, which discards any non-pixel data
// (e.g. embedded scripts, EXIF, trailing bytes) before it is stored.

const MAX_INPUT_BYTES = 5 * 1024 * 1024; // 5 MB
const ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
const OUTPUT_DIMENSION = 256;

export interface SanitizeResult {
  dataUrl?: string;
  error?: string;
}

const readAsDataUrl = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(new Error('Could not read file.'));
    reader.readAsDataURL(file);
  });

const loadImage = (src: string): Promise<HTMLImageElement> =>
  new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Not a valid image.'));
    img.src = src;
  });

/** Validate, re-encode, and downscale an uploaded image to a safe JPEG data URL. */
export const sanitizeImageFile = async (file: File): Promise<SanitizeResult> => {
  if (!ALLOWED_TYPES.includes(file.type)) {
    return { error: 'Unsupported image type. Use PNG, JPEG, WebP, or GIF.' };
  }
  if (file.size > MAX_INPUT_BYTES) {
    return { error: 'Image is too large (max 5 MB).' };
  }

  try {
    const rawDataUrl = await readAsDataUrl(file);
    const img = await loadImage(rawDataUrl);

    const canvas = document.createElement('canvas');
    canvas.width = OUTPUT_DIMENSION;
    canvas.height = OUTPUT_DIMENSION;
    const ctx = canvas.getContext('2d');
    if (!ctx) return { error: 'Could not process image.' };

    // Cover-fit the source into a square canvas.
    const scale = Math.max(OUTPUT_DIMENSION / img.width, OUTPUT_DIMENSION / img.height);
    const w = img.width * scale;
    const h = img.height * scale;
    ctx.drawImage(img, (OUTPUT_DIMENSION - w) / 2, (OUTPUT_DIMENSION - h) / 2, w, h);

    return { dataUrl: canvas.toDataURL('image/jpeg', 0.9) };
  } catch (e) {
    return { error: e instanceof Error ? e.message : 'Could not process image.' };
  }
};
