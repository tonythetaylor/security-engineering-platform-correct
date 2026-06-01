# Deployment

## Locked-down work machine
Use the `web/` folder. Zip it, download it, extract it, and double-click `index.html`.

## GitLab artifact workflow
Push this repo to GitLab and let CI package `security-engineering-platform-web.zip`.

## Standalone desktop
Build with Tauri on a machine with Node/Rust and distribute the generated bundle from `src-tauri/target/release/bundle`.