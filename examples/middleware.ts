// Drop in middleware for Next.js 13, 14 and 15.
// Copy this file to middleware.ts at your project root.

import { middleware } from 'ipgeolocation-vercel-middleware/middleware';

export { middleware };

// Define the matcher here. Next.js reads it at build time and cannot follow a
// value that was re-exported from a package.
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|_next/data|favicon.ico|robots.txt|sitemap.xml|.*\\.(?:css|js|mjs|map|json|txt|xml|ico|png|jpg|jpeg|gif|webp|avif|svg|woff|woff2|ttf|otf|eot|mp4|webm|mp3|pdf|zip)$).*)'
  ]
};
