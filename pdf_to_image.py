#!/usr/bin/env python3
import os
import argparse
import numpy as np
import cv2
from pdf2image import convert_from_path
from PIL import Image


def deskew_image(image, force_rotate=None):
    """
    Correct the skew in an image.
    
    Args:
        image: numpy array of the image
        force_rotate: Force rotation angle (0, 90, 180, 270) or None for auto-detect
        
    Returns:
        Deskewed image as numpy array
    """
    # If force rotation is specified, apply it directly
    if force_rotate is not None:
        (h, w) = image.shape[:2]
        center = (w // 2, h // 2)
        
        if force_rotate == 90:
            M = cv2.getRotationMatrix2D(center, 90, 1.0)
            rotated = cv2.warpAffine(image, M, (h, w), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
            return rotated
        elif force_rotate == 180:
            M = cv2.getRotationMatrix2D(center, 180, 1.0)
            rotated = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
            return rotated
        elif force_rotate == 270:
            M = cv2.getRotationMatrix2D(center, 270, 1.0)
            rotated = cv2.warpAffine(image, M, (h, w), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
            return rotated
        else:
            # 0 degrees or invalid value, return original
            return image
    
    # Auto-detect rotation and skew
    # Convert to grayscale
    if len(image.shape) == 3:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    else:
        gray = image.copy()
    
    # Threshold the image
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    
    # Find contours
    coords = np.column_stack(np.where(thresh > 0))
    
    # Get rotated rectangle
    if len(coords) == 0:
        return image  # No text found, return original
    
    angle = cv2.minAreaRect(coords)[-1]
    
    # Adjust angle
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle
    
    # Rotate the image
    (h, w) = image.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    
    return rotated


def check_orientation(image):
    """
    Try to determine the correct orientation of the image
    based on text orientation detection.
    
    Returns 0, 90, 180, or 270 as the suggested rotation angle.
    """
    # This is a simplified version - in a real implementation, you would
    # use a more sophisticated text orientation detection algorithm
    
    # For now, we'll return 0 (unchanged) and let the user specify rotation if needed
    return 0


def process_pdf(pdf_path, output_dir, dpi=300, split_pages=False, rotation=None, crop_margin=0):
    """
    Convert PDF to images and deskew them.
    
    Args:
        pdf_path: Path to the PDF file
        output_dir: Directory to save output images
        dpi: DPI for the output images (default: 300)
        split_pages: Whether to split double pages in half (default: False)
        rotation: Force specific rotation angle (0, 90, 180, 270)
        crop_margin: Pixels to crop from edges to remove artifacts (default: 0)
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get filename without extension
    file_base = os.path.splitext(os.path.basename(pdf_path))[0]
    
    # Convert PDF to images
    print(f"Converting PDF to images (DPI: {dpi})...")
    images = convert_from_path(pdf_path, dpi=dpi)
    
    total_pages = len(images)
    print(f"Total pages: {total_pages}")
    
    for i, img in enumerate(images):
        print(f"Processing page {i+1}/{total_pages}")
        
        # Convert PIL image to numpy array for OpenCV
        img_array = np.array(img)
        
        # Apply rotation if specified or detect orientation
        if rotation is not None:
            # Force specific rotation
            deskewed = deskew_image(img_array, force_rotate=rotation)
        else:
            # Try to auto-detect and fix skew
            deskewed = deskew_image(img_array)
        
        deskewed_pil = Image.fromarray(deskewed)
        
        # Crop margins if specified to remove artifacts
        if crop_margin > 0:
            width, height = deskewed_pil.size
            deskewed_pil = deskewed_pil.crop((
                crop_margin, 
                crop_margin, 
                width - crop_margin, 
                height - crop_margin
            ))
        
        if split_pages:
            # Split image in half (left and right pages)
            width, height = deskewed_pil.size
            left_img = deskewed_pil.crop((0, 0, width // 2, height))
            right_img = deskewed_pil.crop((width // 2, 0, width, height))
            
            # Save left and right images with zero-padded page numbers
            left_img.save(os.path.join(output_dir, f"{file_base}_page{i+1:04d}_left.png"))
            right_img.save(os.path.join(output_dir, f"{file_base}_page{i+1:04d}_right.png"))
        else:
            # Save the deskewed image with zero-padded page numbers
            deskewed_pil.save(os.path.join(output_dir, f"{file_base}_page{i+1:04d}.png"))
    
    print(f"All images saved to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Convert PDF to deskewed images")
    parser.add_argument("pdf_path", help="Path to the PDF file")
    parser.add_argument("--output-dir", default="output", help="Output directory for images")
    parser.add_argument("--dpi", type=int, default=300, help="DPI for output images")
    parser.add_argument("--split", action="store_true", help="Split double pages in half")
    parser.add_argument("--rotate", type=int, choices=[0, 90, 180, 270], 
                        help="Force rotation angle (0, 90, 180, or 270 degrees)")
    parser.add_argument("--crop", type=int, default=0,
                        help="Crop margin in pixels to remove artifacts from edges")
    
    args = parser.parse_args()
    
    process_pdf(args.pdf_path, args.output_dir, args.dpi, args.split, args.rotate, args.crop)


if __name__ == "__main__":
    main() 