# PhishSentry Icon Generator
#
# Builds simple, neutral Chrome extension icons with only the Python standard
# library. The mark is intentionally minimal so it remains readable at 16px.

import os
import struct
import zlib


def make_chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def write_png(width, height, pixels):
    png = b"\x89PNG\r\n\x1a\n"
    png += make_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))

    raw_data = b""
    for y in range(height):
        raw_data += b"\x00"
        for x in range(width):
            raw_data += struct.pack("BBBB", *pixels[y * width + x])

    png += make_chunk(b"IDAT", zlib.compress(raw_data))
    png += make_chunk(b"IEND", b"")
    return png


def is_inside_rounded_rect(x, y, x0, y0, x1, y1, radius):
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False

    if x0 + radius <= x <= x1 - radius:
        return True

    if y0 + radius <= y <= y1 - radius:
        return True

    corner_x = x0 + radius if x < x0 + radius else x1 - radius
    corner_y = y0 + radius if y < y0 + radius else y1 - radius
    return (x - corner_x) ** 2 + (y - corner_y) ** 2 <= radius ** 2


def is_inside_polygon(x, y, points):
    inside = False
    j = len(points) - 1

    for i, point in enumerate(points):
        xi, yi = point
        xj, yj = points[j]
        intersects = (yi > y) != (yj > y) and x < ((xj - xi) * (y - yi) / (yj - yi) + xi)
        if intersects:
            inside = not inside
        j = i

    return inside


def distance_to_segment(px, py, ax, ay, bx, by):
    abx = bx - ax
    aby = by - ay
    apx = px - ax
    apy = py - ay
    length_squared = abx * abx + aby * aby

    if length_squared == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5

    t = max(0, min(1, (apx * abx + apy * aby) / length_squared))
    projection_x = ax + t * abx
    projection_y = ay + t * aby
    return ((px - projection_x) ** 2 + (py - projection_y) ** 2) ** 0.5


def downsample(pixels, size, scale):
    high_size = size * scale
    downsampled = []

    for y in range(size):
        for x in range(size):
            total_alpha = 0
            total_red = 0
            total_green = 0
            total_blue = 0

            for sample_y in range(scale):
                for sample_x in range(scale):
                    source_x = x * scale + sample_x
                    source_y = y * scale + sample_y
                    red, green, blue, alpha = pixels[source_y * high_size + source_x]
                    total_alpha += alpha
                    total_red += red * alpha
                    total_green += green * alpha
                    total_blue += blue * alpha

            sample_count = scale * scale
            alpha = round(total_alpha / sample_count)

            if total_alpha:
                red = round(total_red / total_alpha)
                green = round(total_green / total_alpha)
                blue = round(total_blue / total_alpha)
            else:
                red = green = blue = 0

            downsampled.append((red, green, blue, alpha))

    return downsampled


def generate_icon_pixels(size):
    scale = 4
    high_size = size * scale
    pixels = []

    background = (247, 248, 250, 255)
    border = (218, 220, 226, 255)
    shield = (29, 29, 31, 255)
    check = (255, 255, 255, 255)

    shield_points = [
        (0.50, 0.20),
        (0.73, 0.31),
        (0.68, 0.63),
        (0.50, 0.80),
        (0.32, 0.63),
        (0.27, 0.31),
    ]

    for y in range(high_size):
        for x in range(high_size):
            nx = (x + 0.5) / high_size
            ny = (y + 0.5) / high_size
            color = (0, 0, 0, 0)

            border_width = max(0.012, 1.0 / size)
            outer = is_inside_rounded_rect(nx, ny, 0.045, 0.045, 0.955, 0.955, 0.20)
            inner = is_inside_rounded_rect(
                nx,
                ny,
                0.045 + border_width,
                0.045 + border_width,
                0.955 - border_width,
                0.955 - border_width,
                0.20 - border_width,
            )

            if outer:
                color = background if inner else border

            if is_inside_polygon(nx, ny, shield_points):
                color = shield

            check_width = 0.052
            check_distance = min(
                distance_to_segment(nx, ny, 0.39, 0.52, 0.47, 0.60),
                distance_to_segment(nx, ny, 0.47, 0.60, 0.63, 0.42),
            )
            if check_distance <= check_width:
                color = check

            pixels.append(color)

    return downsample(pixels, size, scale)


def main():
    os.makedirs("icons", exist_ok=True)

    for size in (16, 48, 128):
        pixels = generate_icon_pixels(size)
        file_path = os.path.join("icons", f"icon{size}.png")
        with open(file_path, "wb") as file:
            file.write(write_png(size, size, pixels))
        print(f"Generated {file_path}")


if __name__ == "__main__":
    main()
