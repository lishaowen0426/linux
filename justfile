set shell := ["bash", "-uc"]

tag:
    make O=. ARCH=arm64 COMPILED_SOURCE=1 tags
    

