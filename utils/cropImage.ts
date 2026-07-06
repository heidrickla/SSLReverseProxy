/**
 * Creates an HTMLImageElement from a URL.
 * This is a helper function for the cropImage utility.
 * @param url The image URL (can be a data URL or blob URL).
 * @returns A promise that resolves with the loaded HTMLImageElement.
 */
const createImage = (url: string): Promise<HTMLImageElement> =>
  new Promise((resolve, reject) => {
    const image = new Image();
    image.addEventListener('load', () => resolve(image));
    image.addEventListener('error', (error) => reject(error));
    // The 'crossOrigin' attribute is not needed for same-origin blob URLs
    // and can cause the image load to fail.
    // image.setAttribute('crossOrigin', 'anonymous');
    image.src = url;
  });

const MAX_AVATAR_DIMENSION = 512; // Max width/height for the final avatar

/**
 * Crops an image to a specified area and resizes it.
 * @param imageSrc The source URL of the image to crop.
 * @param pixelCrop An object with x, y, width, and height of the crop area in pixels.
 * @returns A promise that resolves with the cropped and resized image as a base64 data URL, or null if an error occurs.
 */
async function cropImage(
  imageSrc: string, 
  pixelCrop: { x: number; y: number; width: number; height: number }
): Promise<string | null> {
  try {
    const image = await createImage(imageSrc);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    if (!ctx) {
      console.error('Could not get 2d context from canvas');
      return null;
    }

    const safeCrop = {
      x: Math.round(pixelCrop.x),
      y: Math.round(pixelCrop.y),
      width: Math.round(pixelCrop.width),
      height: Math.round(pixelCrop.height),
    };

    // Set the canvas to the size of the crop area from the original image
    canvas.width = safeCrop.width;
    canvas.height = safeCrop.height;

    // Draw the cropped portion of the source image onto the first canvas
    ctx.drawImage(
      image,
      safeCrop.x,
      safeCrop.y,
      safeCrop.width,
      safeCrop.height,
      0,
      0,
      safeCrop.width,
      safeCrop.height
    );
    
    // Create a second canvas to resize the image for the final avatar
    const finalCanvas = document.createElement('canvas');
    const finalCtx = finalCanvas.getContext('2d');

    if (!finalCtx) {
        console.error('Could not get 2d context from final canvas');
        return null;
    }

    // Set the final canvas size to our desired avatar dimension
    finalCanvas.width = MAX_AVATAR_DIMENSION;
    finalCanvas.height = MAX_AVATAR_DIMENSION;

    // Draw the (potentially large) cropped image onto the smaller final canvas.
    // This resizes the image.
    finalCtx.drawImage(
        canvas,
        0,
        0,
        safeCrop.width,
        safeCrop.height,
        0,
        0,
        MAX_AVATAR_DIMENSION,
        MAX_AVATAR_DIMENSION
    );

    // Get the result as a data URL from the final, resized canvas
    return finalCanvas.toDataURL('image/jpeg');
  } catch (error) {
    console.error('Error cropping image:', error);
    return null;
  }
}

export default cropImage;