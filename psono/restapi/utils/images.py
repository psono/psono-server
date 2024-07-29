from PIL import Image

def crop_to_aspect(img, target_width, target_height):
    """
    Crop an PIL image to target width and height.

    @param img: PIL image
    @param target_width: target width
    @param target_height: target height
    @return: PIL image
    """
    width, height = img.size
    aspect_ratio_image = width / height
    aspect_ratio_target = target_width / target_height

    if aspect_ratio_image > aspect_ratio_target:
        # Image is wider than target aspect ratio
        new_width = int(height * aspect_ratio_target)
        left = (width - new_width) // 2
        right = (width + new_width) // 2
        top = 0
        bottom = height
    else:
        # Image is taller than target aspect ratio
        new_height = int(width / aspect_ratio_target)
        top = (height - new_height) // 2
        bottom = (height + new_height) // 2
        left = 0
        right = width

    img_cropped = img.crop((left, top, right, bottom))
    img_resized = img_cropped.resize((target_width, target_height), Image.Resampling.LANCZOS)

    return img_resized

