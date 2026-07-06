import React, { useState, useCallback } from 'react';
import Cropper, { Area } from 'react-easy-crop';
import Modal from './Modal';
import Button from './Button';
import cropImage from '../utils/cropImage';

interface AvatarEditorModalProps {
    onClose: () => void;
    onSave: (newAvatar: string) => void;
    title?: string;
}

const AvatarEditorModal: React.FC<AvatarEditorModalProps> = ({ onClose, onSave, title = "Edit Avatar" }) => {
    const [imageSrc, setImageSrc] = useState<string | null>(null);
    const [crop, setCrop] = useState({ x: 0, y: 0 });
    const [zoom, setZoom] = useState(1);
    const [croppedAreaPixels, setCroppedAreaPixels] = useState<Area | null>(null);

    const onFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files.length > 0) {
            const file = e.target.files[0];
            // Reject SVG/active content and oversized files. Only accept raster
            // formats; the cropped output is re-encoded to JPEG via canvas.
            const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
            if (!allowed.includes(file.type)) {
                alert('Unsupported image type. Use PNG, JPEG, WebP, or GIF.');
                return;
            }
            if (file.size > 5 * 1024 * 1024) {
                alert('Image is too large (max 5 MB).');
                return;
            }
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.addEventListener('load', () => {
                setImageSrc(reader.result as string);
            });
        }
    };

    const onCropComplete = useCallback((_croppedArea: Area, croppedAreaPixels: Area) => {
        setCroppedAreaPixels(croppedAreaPixels);
    }, []);

    const handleSave = async () => {
        if (!imageSrc || !croppedAreaPixels) return;

        try {
            const croppedImage = await cropImage(imageSrc, croppedAreaPixels);
            if (croppedImage) {
                onSave(croppedImage);
            }
        } catch (e) {
            console.error(e);
            alert('Failed to crop image. Please try again.');
        }
    };

    return (
        <Modal isOpen={true} onClose={onClose} title={title}>
            <div className="space-y-4">
                {!imageSrc ? (
                    <div className="flex justify-center items-center h-48 border-2 border-dashed border-border rounded-lg">
                        <label className="cursor-pointer text-primary hover:underline p-4 text-center">
                            Select an image
                            <input type="file" accept="image/*" className="hidden" onChange={onFileChange} />
                        </label>
                    </div>
                ) : (
                    <>
                        <div className="relative h-64 w-full bg-surface-raised">
                            <Cropper
                                image={imageSrc}
                                crop={crop}
                                zoom={zoom}
                                aspect={1}
                                onCropChange={setCrop}
                                onZoomChange={setZoom}
                                onCropComplete={onCropComplete}
                                cropShape={title.toLowerCase().includes('logo') ? 'rect' : 'round'}
                                showGrid={false}
                            />
                        </div>
                        <div className="flex items-center space-x-4">
                            <label htmlFor="zoom-slider" className="text-sm font-medium text-on-surface-muted">Zoom</label>
                            <input
                                id="zoom-slider"
                                type="range"
                                value={zoom}
                                min={1}
                                max={3}
                                step={0.1}
                                aria-labelledby="Zoom"
                                onChange={(e) => setZoom(Number(e.target.value))}
                                className="w-full h-2 bg-surface-raised rounded-lg appearance-none cursor-pointer"
                            />
                        </div>
                    </>
                )}
                <div className="flex justify-end pt-4 border-t border-border space-x-2">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="button" onClick={handleSave} disabled={!imageSrc}>Save</Button>
                </div>
            </div>
        </Modal>
    );
};

export default AvatarEditorModal;