#!/usr/bin/env python3

import subprocess
from pathlib import Path

content_type_mapping = {
    '.html': "text/html",
    '.css': "text/css",
    '.png': "image/png",
    '.ico': "image/x-icon"
}

static_files = list(Path("./static/").glob("*"))
post_files = list(Path("./posts/").glob("*.md"))


def parse_frontmatter(f: Path):
    with open(f, 'r') as file:
        content = file.read()

    frontmatter = {}

    lines = content.split('\n')
    in_frontmatter = False
    
    for line in lines:
        line = line.strip()
        
        if line == '---':
            in_frontmatter = not in_frontmatter
            continue
            
        if in_frontmatter and ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            frontmatter[key] = value

    return frontmatter

def buffer_identifier(file):
    return f"{file.stem}_{file.suffix[1:]}"

with open("generated_data.h", "w") as generated:
    def write(text):
        generated.write(text)
        
    def write_array(name, content):
        write(f"U8 {name}[] = {{\n")
        for i, byte in enumerate(content):
            if i % 16 == 0:
                write("  ")
            write(f"0x{byte:02x}, ")
            if i % 16 == 15:
                write("\n")
        if len(content) % 16 != 0:
            write("\n")
        write("};\n")
        
    for f in static_files:
        with open(f, "rb") as file:
            content = file.read()
            write_array(buffer_identifier(f), content)

    for f in post_files:
        result = subprocess.run(["pandoc", str(f), 
                    "--from", "markdown", "--to", "html",
                    "--highlight-style", "pygments"], text=True, check=True, capture_output=True)
        content = result.stdout.encode('utf-8')
        write_array(buffer_identifier(f), content)

with open("generated_metadata.h", "w") as generated:
    def write(text):
        generated.write(text)
        
    write("// DO NOT EDIT. THIS IS A GENERATED FILE.\n")
    write("typedef struct RouteMapping {\n")
    write("  S8 path;\n")
    write("  S8 content;\n")
    write("  S8 content_type;\n")
    write("} StaticRouteMapping;\n\n")

    write("typedef struct Post {\n")
    write("  S8 title;\n")
    write("  S8 slug;\n")
    write("  S8 summary;\n")
    write("  S8 tags[16];\n")
    write("  Iz tags_count;\n")
    write("  S8 path;\n")
    write("  S8 html_content;\n")
    write("  S8 created_at;\n")
    write("  S8 updated_at;\n")
    write("} Post;\n\n")

    write("#include \"generated_data.h\"\n\n")

    write("static StaticRouteMapping static_route_mapping[] = {\n")
    for f in static_files:

        content_type = content_type_mapping[str(f.suffix)]
        
        write("(StaticRouteMapping){ ")
        write(f".path = s8(\"/{f.name}\"), ")
        write(f".content = (S8){{{buffer_identifier(f)}, countof({buffer_identifier(f)})}},")
        write(f".content_type = s8(\"{content_type}\"),");
        write(" },\n")
    write("};\n\n")

    write("static Post static_posts[] = {\n")
    for f in post_files:
        frontmatter = parse_frontmatter(f)
        tags = frontmatter.get("tags", "").split(",")
        tags = [t.strip() for t in tags if t]
        tags_count = len(tags)
        write("  (Post){\n")
        write(f"  .title = s8(\"{frontmatter['title']}\"),\n")
        write(f"  .slug = s8(\"{frontmatter['slug']}\"),\n")
        write(f"  .summary = s8(\"{frontmatter['summary']}\"),\n")
        write(f"  .tags = {{")
        for tag in tags:
            write(f"s8(\"{tag}\"), ")
        write(f"}},\n")
        write(f"  .tags_count = {tags_count},\n")
        write(f"  .path = s8(\"/post/{f.name}\"),\n")
        write(f"  .html_content = (S8){{{buffer_identifier(f)}, countof({buffer_identifier(f)})}},\n")
        write(f"  .created_at = s8(\"{frontmatter['created_at']}\"),\n")
        write(f"  .updated_at = s8(\"{frontmatter['updated_at']}\"),\n")
        write("  },\n")
    write("};\n\n")

