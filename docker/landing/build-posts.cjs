// Generates assets/posts.js from src/blog/posts/*.md.
//
// Each post is a markdown file with a simple `key: value` frontmatter block.
// The filename (without .md) is the slug and the URL segment (/blog/<slug>/).
// Output is a window.POSTS array, sorted newest first, loaded by the page
// before app.js so both the teaser and the blog views read from one source.
//
// Run inside the node:lts-alpine build container (see build.sh), where
// /src is the mounted source tree and /out is assets/.
const fs = require("fs");
const path = require("path");
const { marked } = require("marked");

const dir = "/src/blog/posts";
const files = fs.existsSync(dir)
  ? fs.readdirSync(dir).filter(f => f.endsWith(".md")).sort()
  : [];

const posts = files.map(file => {
  const raw = fs.readFileSync(path.join(dir, file), "utf8");
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!m) throw new Error(`${file}: missing or malformed frontmatter`);

  const fm = {};
  for (const line of m[1].split(/\r?\n/)) {
    const i = line.indexOf(":");
    if (i === -1) continue;
    fm[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }

  for (const key of ["title", "tag", "date", "read", "excerpt"]) {
    if (!fm[key]) throw new Error(`${file}: missing frontmatter field "${key}"`);
  }

  return {
    slug: file.replace(/\.md$/, ""),
    title: fm.title,
    tag: fm.tag,
    date: fm.date,
    read: fm.read,
    excerpt: fm.excerpt,
    html: marked.parse(m[2].trim()),
  };
});

posts.sort((a, b) => b.date.localeCompare(a.date));

fs.writeFileSync("/out/posts.js", `window.POSTS = ${JSON.stringify(posts)};\n`);
console.log(`  built assets/posts.js (${posts.length} posts)`);
