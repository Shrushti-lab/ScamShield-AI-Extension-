"""Generate extension PNG icons from code."""
import struct, zlib, os

def create_shield_png(size):
    """Create a simple blue shield PNG icon."""
    pixels = []
    center = size / 2
    for y in range(size):
        row = []
        for x in range(size):
            # Rounded rect background
            rx, ry = x - center, y - center
            corner_r = size * 0.22
            in_rect = True
            # Check if inside rounded rectangle
            if rx < -center + corner_r and ry < -center + corner_r:
                if (rx + center - corner_r)**2 + (ry + center - corner_r)**2 > corner_r**2:
                    in_rect = False
            elif rx > center - corner_r and ry < -center + corner_r:
                if (rx - center + corner_r)**2 + (ry + center - corner_r)**2 > corner_r**2:
                    in_rect = False
            elif rx < -center + corner_r and ry > center - corner_r:
                if (rx + center - corner_r)**2 + (ry - center + corner_r)**2 > corner_r**2:
                    in_rect = False
            elif rx > center - corner_r and ry > center - corner_r:
                if (rx - center + corner_r)**2 + (ry - center + corner_r)**2 > corner_r**2:
                    in_rect = False

            if not in_rect:
                row.extend([0, 0, 0, 0])  # transparent
                continue

            # Blue background #2563eb
            row.extend([37, 99, 235, 255])
        pixels.append(bytes([0] + row))  # filter byte + RGBA

    raw = b''.join(pixels)

    def chunk(ctype, data):
        c = ctype + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)

    header = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
    idat = chunk(b'IDAT', zlib.compress(raw))
    iend = chunk(b'IEND', b'')

    return header + ihdr + idat + iend


if __name__ == '__main__':
    icons_dir = os.path.join(os.path.dirname(__file__), '..', 'extension', 'icons')
    os.makedirs(icons_dir, exist_ok=True)

    for size in [16, 48, 128]:
        data = create_shield_png(size)
        path = os.path.join(icons_dir, f'icon{size}.png')
        with open(path, 'wb') as f:
            f.write(data)
        print(f"Created {path} ({len(data)} bytes)")
