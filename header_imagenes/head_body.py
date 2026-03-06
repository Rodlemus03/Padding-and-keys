
converted_image = r'tux.ppm'
# Step 3: Separate header and body
with open(converted_image, "rb") as f:
    lines = f.readlines()

header = lines[:3]  # Assuming the header is the first 3 lines
body = b"".join(lines[3:])

# Additional: Save header and body separately
with open("header.ppm", "wb") as f:
    f.writelines(header)

with open("body.ppm", "wb") as f:
    f.write(body)
