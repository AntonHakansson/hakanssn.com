#!/usr/bin/env bash

mkdir -p generated
xxd -i static/style.css > generated/style.css.h
xxd -i static/favicon.ico > generated/favicon.ico.h
xxd -i static/logo.png > generated/logo.png.h

find posts/ -name "*.md" -exec sh -c '
  name=$(basename "$1" .md)
  pandoc "$1" \
    --from markdown \
    --to html5 \
    --highlight-style=pygments \
    > ./generated/post_${name}.html
' _ {} \;
xxd -i generated/*.html > generated/posts.h

bash main.c
