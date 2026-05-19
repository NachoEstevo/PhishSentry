# PhishSentry Programmatic Icon Generator (Pure Python Runner)
# 
# Draws high-fidelity, glowing electric blue security shields with checkmarks
# at 16x16, 48x48, and 128x128 pixel sizes. Uses only standard libraries
# (zlib, struct) to output perfect, transparent PNG graphics.

import os
import zlib
import struct
import math

def make_chunk(tag, data):
    return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data))

def write_png(width, height, pixels):
    # PNG File Signature
    png = b'\x89PNG\r\n\x1a\n'
    
    # IHDR Chunk
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    png += make_chunk(b'IHDR', ihdr)
    
    # IDAT Chunk (zlib compressed pixel rows)
    raw_data = b''
    for y in range(height):
        raw_data += b'\x00' # Filter byte 0 (None)
        for x in range(width):
            r, g, b, a = pixels[y * width + x]
            raw_data += struct.pack('BBBB', r, g, b, a)
            
    idat = zlib.compress(raw_data)
    png += make_chunk(b'IDAT', idat)
    
    # IEND Chunk
    png += make_chunk(b'IEND', b'')
    return png

def distance_to_segment(px, py, ax, ay, bx, by):
    # Distance from point (px, py) to line segment AB
    abx = bx - ax
    aby = by - ay
    apx = px - ax
    apy = py - ay
    
    ab_len_sq = abx*abx + aby*aby
    if ab_len_sq == 0:
        return math.sqrt(apx*apx + apy*apy)
        
    t = max(0, min(1, (apx*abx + apy*aby) / ab_len_sq))
    proj_x = ax + t * abx
    proj_y = ay + t * aby
    
    return math.sqrt((px - proj_x)**2 + (py - proj_y)**2)

def generate_shield_pixels(size):
    pixels = []
    
    for y in range(size):
        for x in range(size):
            # Normalize coordinates to [-1.0, 1.0]
            dx = (x - (size - 1) / 2.0) / (size / 2.0)
            dy = (y - (size - 1) / 2.0) / (size / 2.0)
            
            # Pad slightly so shield doesn't touch boundary
            dx /= 0.9
            dy /= 0.9
            
            # --- SHIELD BOUNDARY FORMULAS ---
            # Top Curve
            top_y = -0.75 + 0.15 * (dx ** 2)
            # Bottom Point Curves
            bottom_y = 0.75 - 1.5 * (abs(dx) ** 2)
            
            # Left & Right side bounds
            in_x_bound = abs(dx) <= 0.75
            
            # Determine if point is inside shield shape
            is_inside = False
            if in_x_bound and dy >= top_y:
                # Shape pointing downwards
                # Tip is at (0, 0.75) and sides curve up to (0.75, -0.09)
                edge_y = 0.75 - 1.12 * abs(dx) - 0.3 * (dx ** 2)
                if dy <= edge_y:
                    is_inside = True
                    
            # Compute distance to edge for glow/border heuristics
            # Approximate distance to shield outline
            edge_dist = 999.0
            if in_x_bound:
                dist_top = abs(dy - top_y)
                edge_y = 0.75 - 1.12 * abs(dx) - 0.3 * (dx ** 2)
                dist_bottom = abs(dy - edge_y)
                dist_side = abs(abs(dx) - 0.75) if dy < 0 else 999.0
                edge_dist = min(dist_top, dist_bottom, dist_side)
                
            # Default pixel values (transparent)
            r, g, b, a = 0, 0, 0, 0
            
            if is_inside:
                # Draw checkmark inside
                # Segment 1: (-0.22, 0.05) to (-0.05, 0.22)
                # Segment 2: (-0.05, 0.22) to (0.32, -0.15)
                dist_check = min(
                    distance_to_segment(dx, dy, -0.22, 0.05, -0.05, 0.22),
                    distance_to_segment(dx, dy, -0.05, 0.22, 0.32, -0.15)
                )
                
                # Checkmark thickness (normalized)
                check_thickness = 0.075
                
                if dist_check <= check_thickness:
                    # Glowing emerald checkmark
                    r, g, b, a = 16, 185, 129, 255
                elif edge_dist <= 0.08:
                    # Glowing electric cyan border
                    r, g, b, a = 0, 242, 254, 255
                else:
                    # Radial gradient inside shield (Navy to deep space blue)
                    dist_to_center = math.sqrt(dx**2 + (dy + 0.1)**2)
                    factor = min(1.0, dist_to_center / 0.8)
                    # Interpolate: center is brighter blue, outer is dark navy
                    r = int(11 + (15 - 11) * factor)
                    g = int(80 + (15 - 80) * factor)
                    b = int(180 + (25 - 180) * factor)
                    a = 230 # high opacity glassmorphism
            else:
                # Outer Glow: if just outside the shield edge, add a soft blue neon aura
                if edge_dist <= 0.12 and dy >= top_y - 0.12:
                    # Distance factor
                    glow_factor = (0.12 - edge_dist) / 0.12
                    r = 0
                    g = 242
                    b = 254
                    a = int(60 * (glow_factor ** 2)) # soft fadeout
                    
            pixels.append((r, g, b, a))
            
    return pixels

def main():
    icons_dir = "icons"
    if not os.path.exists(icons_dir):
        os.makedirs(icons_dir)
        print(f"Created '{icons_dir}' directory.")
        
    sizes = [16, 48, 128]
    for size in sizes:
        pixels = generate_shield_pixels(size)
        png_data = write_png(size, size, pixels)
        
        file_path = os.path.join(icons_dir, f"icon{size}.png")
        with open(file_path, "wb") as f:
            f.write(png_data)
            
        print(f"Successfully generated {size}x{size} icon: {file_path}")

if __name__ == "__main__":
    main()
