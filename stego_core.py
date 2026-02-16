from PIL import Image
import os

def xor_encrypt(text, key):
    """Encrypt text using XOR cipher with repeating key"""
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return result

def xor_decrypt(text, key):
    """Decrypt XOR encrypted text (same as encrypt)"""
    return xor_encrypt(text, key)

def hide_text(image_path, message, password, output_path):
    """Hide encrypted text in image LSBs"""
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Input image not found: {image_path}")
    
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()

    encrypted_text = xor_encrypt(message, password) + "#####"
    binary_text = ''.join(format(ord(c), '08b') for c in encrypted_text)
    
    if len(binary_text) > img.width * img.height * 3:
        raise ValueError("Message too long for image capacity")

    index = 0
    length = len(binary_text)

    for y in range(img.height):
        for x in range(img.width):
            if index + 2 < length:
                r, g, b = pixels[x, y]
                
                r = (r & ~1) | int(binary_text[index])
                g = (g & ~1) | int(binary_text[index + 1])
                b = (b & ~1) | int(binary_text[index + 2])
                
                pixels[x, y] = (r, g, b)
                index += 3
            else:
                break
        else:
            continue
        break

    img.save(output_path)
    return True

def extract_text(image_path, password):
    """Extract and decrypt hidden text from image"""
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()

    binary_data = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)

    encrypted_message = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) < 8:
            break
        char = chr(int(byte, 2))
        encrypted_message += char
        if encrypted_message.endswith("#####"):
            break

    encrypted_message = encrypted_message.replace("#####", "")
    decrypted_message = xor_decrypt(encrypted_message, password)
    return decrypted_message
