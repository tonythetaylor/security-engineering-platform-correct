import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

const root = process.cwd();
const out = path.join(root, 'releases');
fs.mkdirSync(out, { recursive: true });
const zipPath = path.join(out, 'security-engineering-platform-web.zip');
if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);
execFileSync('zip', ['-r', zipPath, 'web', 'README.md', '.gitignore'], { stdio: 'inherit' });
console.log(`Created ${zipPath}`);
